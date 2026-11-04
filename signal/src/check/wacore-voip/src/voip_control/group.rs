//! Runtime state machine for group-call membership and participant controls.
//!
//! The server owns the roster. Updates are transaction ordered and membership never merges
//! incrementally: an accepted roster replaces the previous one atomically. Optional relay omission
//! means no allocation refresh, so the last usable relay is carried across roster-only updates.

use std::collections::{HashMap, HashSet};

use wacore_binary::Jid;

use crate::types::group_call::{
  GROUP_CALL_MAX_PARTICIPANTS, GroupCallDevice, GroupCallParticipant, GroupCallUpdate, ScreenShare,
  ScreenShareState, WaitingRoom,
};

/// Result of applying an authoritative group or waiting-room update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GroupStateApply {
  Applied,
  Stale,
  UnknownCall,
  IdentityMismatch,
  InvalidSnapshot,
}

/// Portable per-call state for authoritative snapshots and participant controls.
#[derive(Debug, Clone)]
pub struct GroupCallState {
  call_id: String,
  call_creator: Jid,
  snapshot: Option<GroupCallUpdate>,
  waiting_room: Option<WaitingRoom>,
  waiting_room_transaction: Option<u32>,
  raised_hands: HashSet<Jid>,
  screen_shares: HashMap<Jid, ScreenShare>,
  /// A rekey the initial ack asked for and transaction zero could not carry: the request is
  /// parked when that ack is admitted and answered by the first ordered roster. It is the
  /// outstanding request, never wire state — nothing about it is serialized onto a snapshot.
  owed_rekey: bool,
}

impl GroupCallState {
  pub fn new(call_id: impl Into<String>, call_creator: Jid) -> Self {
    Self {
      call_id: call_id.into(),
      call_creator,
      snapshot: None,
      waiting_room: None,
      waiting_room_transaction: None,
      raised_hands: HashSet::new(),
      screen_shares: HashMap::new(),
      owed_rekey: false,
    }
  }

  pub fn snapshot(&self) -> Option<&GroupCallUpdate> {
    self.snapshot.as_ref()
  }

  pub fn waiting_room(&self) -> Option<&WaitingRoom> {
    self.waiting_room.as_ref()
  }

  pub fn raised_hands(&self) -> &HashSet<Jid> {
    &self.raised_hands
  }

  pub fn screen_shares(&self) -> &HashMap<Jid, ScreenShare> {
    &self.screen_shares
  }

  /// Advance the authoritative roster and relay allocation on their independent transactions.
  pub fn apply_update(&mut self, update: GroupCallUpdate) -> GroupStateApply {
    self.apply_snapshot(update, SnapshotAdmission::Strict)
  }

  /// Admit the snapshot an initial `offer` ack carries, which names the roster the call service
  /// accepted and not yet the two update-plane integers: no roster transaction has been applied
  /// while that ack is in flight, and the ack declares no connected limit. Absent them, an ack
  /// that omits either is the state the call is actually in, not a malformed roster.
  ///
  /// Bounded to the first snapshot a call admits: every `group_update` and every later roster
  /// still states both, so the relaxation cannot carry past the ack it exists for.
  pub fn apply_initial_offer_ack(&mut self, update: GroupCallUpdate) -> GroupStateApply {
    self.apply_snapshot(update, SnapshotAdmission::InitialOfferAck)
  }

  fn apply_snapshot(
    &mut self,
    mut update: GroupCallUpdate,
    admission: SnapshotAdmission,
  ) -> GroupStateApply {
    if !self.matches_identity(&update.call_id, &update.call_creator) {
      return GroupStateApply::IdentityMismatch;
    }
    // Identity includes the group the roster belongs to, so a stated `group_jid` is
    // reconciled — and a conflict refused — before any admission decision. Checked here,
    // an overtaken partial ack with another group's identity reports `Stale` for a roster
    // it was never part of, and the offer path accepts `Stale` while keeping the held
    // snapshot beside that ack's relay.
    if let Some(current_group_jid) = self
      .snapshot
      .as_ref()
      .and_then(|snapshot| snapshot.group_jid.as_ref())
    {
      match update.group_jid.as_ref() {
        Some(group_jid) if group_jid != current_group_jid => {
          return GroupStateApply::IdentityMismatch;
        }
        None => update.group_jid = Some(current_group_jid.clone()),
        Some(_) => {}
      }
    }
    let admission = match admission {
      // Only a state that holds no snapshot yet can be admitting the ack's partial one.
      SnapshotAdmission::InitialOfferAck if self.snapshot.is_none() => {
        SnapshotAdmission::InitialOfferAck
      }
      // A roster has been ordered since this ack was sent, so a partial one is the ack
      // being overtaken rather than a malformed roster: report it stale — the offer path
      // already tolerates `Stale` — and leave the committed roster and its relay alone.
      // An ack that states both integers is an ordered roster and answers to the strict
      // rules like any other.
      SnapshotAdmission::InitialOfferAck
        if update.transaction_id == 0 || update.connected_limit == 0 =>
      {
        return GroupStateApply::Stale;
      }
      _ => SnapshotAdmission::Strict,
    };
    if !valid_group_snapshot(&update, admission) {
      return GroupStateApply::InvalidSnapshot;
    }

    let advances_relay = update.relay.as_ref().is_some_and(|incoming| {
      self
        .snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.relay.as_ref())
        .is_none_or(|held| {
          incoming
            .transaction_id
            .is_some_and(|next| held.transaction_id.is_none_or(|previous| next > previous))
        })
    });
    if let Some(current) = self.snapshot.as_mut()
      && update.transaction_id <= current.transaction_id
    {
      // An older roster may supply the first or a newer allocation, after identity
      // validation, but cannot replace the roster or mutate participant controls.
      if advances_relay {
        current.relay = update.relay;
        return GroupStateApply::Applied;
      }
      return GroupStateApply::Stale;
    }
    // Roster-only updates omit unchanged PIDs. Stabilize the candidate before validation:
    // an explicit reassignment can collide with an inherited PID (including PID zero).
    if let Some(previous) = self.snapshot.as_ref() {
      let mut known: HashMap<_, _> = previous
        .participants
        .iter()
        .flat_map(|participant| &participant.devices)
        .filter_map(|device| device.pid.map(|pid| (device.jid.clone(), pid)))
        .collect();
      // Exact namespace advertisements take precedence; mapped aliases are fallback only.
      for participant in &previous.participants {
        for device in &participant.devices {
          if let Some(pid) = device.pid
            && let Some(alias) =
              mapped_group_device(&participant.jid, participant.pn.as_ref(), &device.jid)
          {
            known.entry(alias).or_insert(pid);
          }
        }
      }
      for participant in update.participants.iter_mut().filter(|p| p.is_connected()) {
        for device in &mut participant.devices {
          if device.pid.is_none() {
            device.pid = known.get(&device.jid).copied().or_else(|| {
              mapped_group_device(&participant.jid, participant.pn.as_ref(), &device.jid)
                .and_then(|alias| known.get(&alias).copied())
            });
          }
        }
      }
    }
    if !advances_relay {
      // Roster progress cannot revoke or roll back a held allocation. An absent/unknown
      // relay transaction provides no evidence to replace an explicitly known epoch.
      update.relay = self
        .snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.relay.clone());
    }
    if !valid_group_snapshot(&update, admission) {
      return GroupStateApply::InvalidSnapshot;
    }
    // Only the fully validated candidate may consume a transaction or alter participant controls.
    let canonical = update
      .participants
      .iter()
      .filter(|participant| participant.is_connected())
      .flat_map(|participant| {
        let jid = participant.jid.to_non_ad();
        std::iter::once((jid.clone(), jid.clone()))
          .chain(participant.pn.as_ref().map(|pn| (pn.to_non_ad(), jid)))
      })
      .collect::<HashMap<_, _>>();
    self.raised_hands = self
      .raised_hands
      .drain()
      .filter_map(|participant| canonical.get(&participant).cloned())
      .collect();
    if update.media == "audio" {
      self.screen_shares.clear();
    } else {
      self.screen_shares = self
        .screen_shares
        .drain()
        .filter_map(|(participant, screen_share)| {
          canonical
            .get(&participant)
            .cloned()
            .map(|canonical| (canonical, screen_share))
        })
        .collect();
    }
    let owed_rekey = matches!(admission, SnapshotAdmission::InitialOfferAck)
      && update.rekey_requested
      && update.transaction_id == 0;
    self.snapshot = Some(update);
    // Set-only: the first ordered roster commits through this same function afterwards,
    // and that commit is the answer the request waits for — it must never clear it before
    // the caller takes it.
    if owed_rekey {
      self.owed_rekey = true;
    }
    GroupStateApply::Applied
  }

  /// Take the rekey request the initial ack left outstanding for this call, if any.
  ///
  /// A transaction-zero ack cannot name a fan-out transaction (`build_group_enc_rekey`
  /// refuses zero), so its request is parked at admission and answered by the first ordered
  /// roster that arrives — whether or not that update repeats the flag. Consumed exactly once.
  pub fn take_owed_rekey(&mut self) -> bool {
    std::mem::take(&mut self.owed_rekey)
  }

  /// Replace waiting-room state when its optional transaction is not stale.
  pub fn apply_waiting_room(&mut self, room: WaitingRoom) -> GroupStateApply {
    if !self.matches_identity(&room.call_id, &room.call_creator) {
      return GroupStateApply::IdentityMismatch;
    }
    if self
      .waiting_room
      .as_ref()
      .is_some_and(|current| current.link_token != room.link_token || current.media != room.media)
    {
      return GroupStateApply::IdentityMismatch;
    }
    if let (Some(current), Some(next)) = (self.waiting_room_transaction, room.transaction_id)
      && next <= current
    {
      return GroupStateApply::Stale;
    }
    if let Some(transaction_id) = room.transaction_id {
      self.waiting_room_transaction = Some(
        self
          .waiting_room_transaction
          .map_or(transaction_id, |current| current.max(transaction_id)),
      );
    }
    self.waiting_room = Some(room);
    GroupStateApply::Applied
  }

  pub fn set_waiting_room_enabled(&mut self, enabled: bool) -> bool {
    self.waiting_room.as_mut().is_some_and(|room| {
      room.enabled = enabled;
      true
    })
  }

  pub fn set_raised_hand(&mut self, participant: &Jid, raised: bool) {
    let participant = participant.to_non_ad();
    if raised {
      self.raised_hands.insert(participant);
    } else {
      self.raised_hands.remove(&participant);
    }
  }

  pub fn set_screen_share(&mut self, participant: &Jid, screen_share: ScreenShare) {
    let participant = participant.to_non_ad();
    if screen_share.state == ScreenShareState::Stopped {
      self.screen_shares.remove(&participant);
    } else {
      self.screen_shares.insert(participant, screen_share);
    }
  }

  fn matches_identity(&self, call_id: &str, creator: &Jid) -> bool {
    self.call_id == call_id && self.call_creator == *creator
  }
}

// PID continuity alone may use the roster's explicit PN/LID mapping. Preserve the full device
// suffix and never rewrite the stored JID: media/Signal namespaces and their key derivations differ.
fn mapped_group_device(owner: &Jid, pn: Option<&Jid>, device: &Jid) -> Option<Jid> {
  let pn = pn?;
  if owner.server != wacore_binary::Server::Lid
    || pn.server != wacore_binary::Server::Pn
    || owner.integrator != pn.integrator
  {
    return None;
  }
  let user = device.to_non_ad();
  let alternate = if user == owner.to_non_ad() {
    pn
  } else if user == pn.to_non_ad() {
    owner
  } else {
    return None;
  };
  let mut alias = device.clone();
  alias.user = alternate.user.clone();
  alias.server = alternate.server;
  Some(alias)
}

impl crate::stats::HeapSize for GroupCallState {
  fn heap_bytes(&self) -> usize {
    use core::mem::size_of;

    use crate::stats::HeapSize;

    self.call_id.heap_bytes()
      + self.call_creator.heap_bytes()
      + self.snapshot.as_ref().map_or(0, HeapSize::heap_bytes)
      + self.waiting_room.as_ref().map_or(0, HeapSize::heap_bytes)
      + self.raised_hands.capacity() * size_of::<Jid>()
      + self
        .raised_hands
        .iter()
        .map(HeapSize::heap_bytes)
        .sum::<usize>()
      + self.screen_shares.capacity() * size_of::<(Jid, ScreenShare)>()
      + self
        .screen_shares
        .keys()
        .map(HeapSize::heap_bytes)
        .sum::<usize>()
  }
}

/// Which snapshot a call is being asked to admit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotAdmission {
  /// A roster the call service has already ordered: both update-plane integers are stated.
  Strict,
  /// The first snapshot of an outgoing group call's `offer` ack, which does not state them yet.
  InitialOfferAck,
}

fn valid_group_snapshot(update: &GroupCallUpdate, admission: SnapshotAdmission) -> bool {
  // The ack's partial snapshot leaves the ordering transaction unallocated and declares no
  // connected limit, which `0` is how it says so; a strict roster that writes `0` there is
  // malformed rather than absent, and a declared limit still cannot be exceeded by its roster.
  let partial = admission == SnapshotAdmission::InitialOfferAck;
  let connected = update
    .participants
    .iter()
    .filter(|participant| participant.is_connected())
    .count();
  let active_devices = update
    .participants
    .iter()
    .filter(|participant| participant.is_connected())
    .flat_map(|participant| participant.devices.iter())
    .filter(|device| device.pid.is_some())
    .count();
  if (!partial && (update.transaction_id == 0 || update.connected_limit == 0))
    || update.connected_limit as usize > GROUP_CALL_MAX_PARTICIPANTS
    || update.participants.len() > GROUP_CALL_MAX_PARTICIPANTS
    || active_devices > GROUP_CALL_MAX_PARTICIPANTS
    || (update.connected_limit != 0 && connected > update.connected_limit as usize)
    || !matches!(update.media.as_str(), "audio" | "video")
  {
    return false;
  }
  // The relay's transaction_id numbers relay allocations, not roster transactions (live: relay
  // transaction-id 1 inside group_update transaction-id 13), so the two are not compared.

  let mut users = HashSet::with_capacity(update.participants.len());
  let mut pids = HashSet::new();
  let mut devices = HashSet::new();
  update.participants.iter().all(|participant| {
    users.insert(participant.jid.to_non_ad())
      && participant
        .pn
        .as_ref()
        .is_none_or(|pn| users.insert(pn.to_non_ad()))
      && participant.devices.iter().all(|device| {
        let device_user = device.jid.to_non_ad();
        (device_user == participant.jid.to_non_ad()
                    || participant
                        .pn
                        .as_ref()
                        .is_some_and(|pn| device_user == pn.to_non_ad()))
                    && devices.insert(device.jid.clone())
                    // pid 0 is a real participant id: the call creator gets it.
                    && device.pid.is_none_or(|pid| pids.insert(pid))
      })
  }) && validate_group_snapshot_for_media(update).is_ok()
}

/// Reject a roster whose connected devices collide on a participant identity or an SSRC.
///
/// The media engine depends on this before it routes a packet: a duplicate SSRC would let one
/// participant's media land in another's decoder. The check is pure (HKDF over the call-id and
/// participant id via the neutral `ssrc` module), so it belongs to the control plane and runs the
/// same whether or not the engine is compiled.
pub(crate) fn validate_group_snapshot_for_media(update: &GroupCallUpdate) -> Result<(), ()> {
  use crate::voip_control::ssrc::{
    APP_DATA_SSRC_SLOT_WORD, VIDEO_SSRC_SLOT_WORD, derive_wasm_participant_ssrc,
    format_e2e_srtp_participant_id,
  };

  const RELAY_STREAM_SLOT_COUNT: u32 = 9;
  let mut pids = HashSet::new();
  let mut devices = HashSet::new();
  let mut audio = HashSet::new();
  let mut video = HashSet::new();
  let mut app_data = HashSet::new();
  let mut rtcp = HashSet::new();
  for device in update
    .participants
    .iter()
    .filter(|participant| participant.state.as_deref() == Some("connected"))
    .flat_map(|participant| &participant.devices)
  {
    let Some(pid) = device.pid else {
      continue;
    };
    let participant_id = format_e2e_srtp_participant_id(&device.jid.to_string());
    if !pids.insert(pid) || !devices.insert(participant_id.clone()) {
      return Err(());
    }
    let audio_ssrc = derive_wasm_participant_ssrc(&update.call_id, &participant_id, 0);
    let video_ssrc =
      derive_wasm_participant_ssrc(&update.call_id, &participant_id, VIDEO_SSRC_SLOT_WORD);
    let app_data_ssrc =
      derive_wasm_participant_ssrc(&update.call_id, &participant_id, APP_DATA_SSRC_SLOT_WORD);
    if !audio.insert(audio_ssrc) || !video.insert(video_ssrc) || !app_data.insert(app_data_ssrc) {
      return Err(());
    }
    for slot_word in 0..RELAY_STREAM_SLOT_COUNT {
      let rtcp_ssrc = derive_wasm_participant_ssrc(&update.call_id, &participant_id, slot_word);
      if !rtcp.insert(rtcp_ssrc) {
        return Err(());
      }
    }
  }
  Ok(())
}

///
/// Matches on the user (LID or its PN alias) and the device id together: the same device id on a
/// different account is a different device, and a PN alias of the local account is still local.
pub(crate) fn group_device_is_local(
  participant: &GroupCallParticipant,
  device: &GroupCallDevice,
  local_device: &Jid,
) -> bool {
  use wacore_binary::JidExt;

  let owns_local_user = participant.jid.is_same_user_as(local_device)
    || participant
      .pn
      .as_ref()
      .is_some_and(|pn| pn.is_same_user_as(local_device));
  owns_local_user
    && device.jid.device == local_device.device
    && (device.jid.is_same_user_as(&participant.jid)
      || participant
        .pn
        .as_ref()
        .is_some_and(|pn| device.jid.is_same_user_as(pn)))
}

/// Whether a roster's relay block is usable for media: a valid warp tag width, a non-empty key and
/// token, and an endpoint with a parseable IPv4 and a non-zero port.
///
/// Pure validation, so the control plane can reject an unusable relay snapshot with the engine off.
/// The engine's richer form additionally derives the allocate material; this checks everything that
/// can make a snapshot invalid without touching crypto.
pub(crate) fn validate_group_relay_update(update: &GroupCallUpdate) -> Result<(), ()> {
  use crate::voip_control::relay_parse::WEB_CLIENT_RELAY_PORT;

  let Some(relay) = update.relay.as_ref() else {
    return Ok(());
  };
  let warp_mi_tag_len = relay.warp_mi_tag_len.unwrap_or(4);
  if !(1..=20).contains(&warp_mi_tag_len) || relay.key.is_empty() {
    return Err(());
  }
  let usable = |endpoint: &&crate::types::group_call::GroupCallRelayEndpoint| {
    !endpoint.is_fna
      && endpoint.ipv4.is_some()
      && endpoint.port.is_some_and(|port| port != 0)
      && relay
        .tokens
        .get(endpoint.token_id as usize)
        .is_some_and(|token| !token.is_empty())
  };
  let endpoint = relay
    .endpoints
    .iter()
    .filter(usable)
    .find(|endpoint| endpoint.port == Some(WEB_CLIENT_RELAY_PORT))
    .or_else(|| relay.endpoints.iter().find(usable))
    .ok_or(())?;
  let ipv4 = endpoint.ipv4.as_deref().ok_or(())?;
  ipv4.parse::<std::net::Ipv4Addr>().map_err(|_| ())?;
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::types::group_call::{GroupCallDevice, GroupCallParticipant, GroupCallRelay};
  use crate::voip_control::ssrc::{derive_wasm_participant_ssrc, format_e2e_srtp_participant_id};
  use wacore_binary::Server;

  fn creator() -> Jid {
    Jid::new("100001", Server::Lid).with_device(1)
  }

  fn participant(user: &str, state: &str, pid: u32) -> GroupCallParticipant {
    GroupCallParticipant {
      jid: Jid::new(user, Server::Lid),
      pn: None,
      state: Some(state.to_string()),
      participant_type: None,
      error: None,
      devices: vec![GroupCallDevice {
        jid: Jid::new(user, Server::Lid).with_device(1),
        platform: Some("web".to_string()),
        pid: Some(pid),
        capability_version: None,
        capability: Vec::new(),
      }],
    }
  }

  fn update(transaction_id: u32, users: Vec<GroupCallParticipant>) -> GroupCallUpdate {
    GroupCallUpdate {
      call_id: "CALL".to_string(),
      call_creator: creator(),
      group_jid: None,
      transaction_id,
      media: "video".to_string(),
      connected_limit: 32,
      joinable: true,
      av_upgradable: true,
      rekey_requested: false,
      participants: users,
      relay: None,
    }
  }

  fn waiting_room(transaction_id: Option<u32>) -> WaitingRoom {
    WaitingRoom {
      call_id: "CALL".to_string(),
      call_creator: creator(),
      link_token: "TEST-CALL-LINK".to_string(),
      media: crate::types::group_call::CallLinkMedia::Audio,
      enabled: true,
      is_admin: false,
      transaction_id,
      users: Vec::new(),
    }
  }

  #[test]
  fn snapshots_are_transaction_ordered_and_clear_departed_controls() {
    let mut state = GroupCallState::new("CALL", creator());
    let alice = Jid::new("200002", Server::Lid);
    assert_eq!(
      state.apply_update(update(
        3,
        vec![
          participant("100001", "connected", 1),
          participant("200002", "connected", 2),
        ],
      )),
      GroupStateApply::Applied
    );
    state.set_raised_hand(&alice, true);
    state.set_screen_share(
      &alice,
      ScreenShare {
        state: ScreenShareState::Started,
        version: 2,
        screen_share_id: Some(7),
      },
    );

    assert_eq!(
      state.apply_update(update(3, vec![participant("100001", "connected", 1)],)),
      GroupStateApply::Stale
    );
    assert!(state.raised_hands().contains(&alice));
    assert_eq!(
      state.apply_update(update(4, vec![participant("100001", "connected", 1)],)),
      GroupStateApply::Applied
    );
    assert!(state.raised_hands().is_empty());
    assert!(state.screen_shares().is_empty());
  }

  #[test]
  fn audio_downgrade_clears_screen_share_state() {
    let mut state = GroupCallState::new("CALL", creator());
    let alice = Jid::new("200002", Server::Lid);
    assert_eq!(
      state.apply_update(update(
        1,
        vec![
          participant("100001", "connected", 1),
          participant("200002", "connected", 2),
        ],
      )),
      GroupStateApply::Applied
    );
    state.set_screen_share(
      &alice,
      ScreenShare {
        state: ScreenShareState::Started,
        version: 2,
        screen_share_id: Some(7),
      },
    );

    let mut audio = update(
      2,
      vec![
        participant("100001", "connected", 1),
        participant("200002", "connected", 2),
      ],
    );
    audio.media = "audio".to_string();
    assert_eq!(state.apply_update(audio), GroupStateApply::Applied);
    assert!(
      state.screen_shares().is_empty(),
      "audio snapshots cannot retain a call-wide screen-share claim"
    );
  }

  #[test]
  fn roster_only_updates_retain_the_last_usable_relay() {
    let mut state = GroupCallState::new("CALL", creator());
    let relay = GroupCallRelay::builder()
      .transaction_id(1)
      .self_pid(7)
      .uuid("RELAY-UUID".to_string())
      .participant_uuid("PARTICIPANT-UUID".to_string())
      .attribute_padding(false)
      .warp_mi_tag_len(16)
      .endpoints(Vec::new())
      .build();
    let mut admitted = update(1, vec![participant("100001", "connected", 1)]);
    admitted.relay = Some(relay.clone());
    assert_eq!(state.apply_update(admitted), GroupStateApply::Applied);

    assert_eq!(
      state.apply_update(update(2, vec![participant("100001", "connected", 1)],)),
      GroupStateApply::Applied
    );
    assert_eq!(
      state
        .snapshot()
        .and_then(|snapshot| snapshot.relay.as_ref()),
      Some(&relay),
      "an omitted relay is a roster-only update, not allocation revocation"
    );
  }

  fn relay_tx(transaction_id: u32) -> GroupCallRelay {
    GroupCallRelay::builder()
      .transaction_id(transaction_id)
      .self_pid(1)
      .uuid("RELAY-UUID".to_string())
      .participant_uuid("PARTICIPANT-UUID".to_string())
      .attribute_padding(false)
      .warp_mi_tag_len(16)
      .endpoints(Vec::new())
      .build()
  }

  fn without_pid(mut participant: GroupCallParticipant) -> GroupCallParticipant {
    for device in &mut participant.devices {
      device.pid = None;
    }
    participant
  }

  #[test]
  fn relay_transaction_is_independent_of_the_roster_transaction() {
    let mut state = GroupCallState::new("CALL", creator());
    let mut snapshot = update(13, vec![participant("100001", "connected", 1)]);
    snapshot.relay = Some(relay_tx(1));
    assert_eq!(state.apply_update(snapshot), GroupStateApply::Applied);
    assert_eq!(
      state
        .snapshot()
        .and_then(|snapshot| snapshot.relay.as_ref())
        .and_then(|relay| relay.transaction_id),
      Some(1)
    );
  }

  #[test]
  fn a_late_relay_on_an_older_transaction_is_adopted_without_regressing_the_roster() {
    let mut state = GroupCallState::new("CALL", creator());
    let newer = update(
      15,
      vec![
        participant("100001", "connected", 1),
        participant("200002", "connected", 2),
      ],
    );
    assert_eq!(state.apply_update(newer), GroupStateApply::Applied);

    let mut older = update(13, vec![participant("100001", "connected", 1)]);
    older.relay = Some(relay_tx(1));
    assert_eq!(state.apply_update(older), GroupStateApply::Applied);
    let snapshot = state.snapshot().expect("snapshot");
    assert_eq!(snapshot.transaction_id, 15, "the newer roster stays");
    assert_eq!(snapshot.participants.len(), 2);
    assert!(snapshot.relay.is_some(), "the late relay is adopted");

    let mut stale = update(14, vec![participant("100001", "connected", 1)]);
    stale.relay = Some(relay_tx(0));
    assert_eq!(
      state.apply_update(stale),
      GroupStateApply::Stale,
      "an older relay never replaces one already held"
    );
  }

  #[test]
  fn newer_relay_allocation_does_not_depend_on_roster_freshness() {
    let mut state = GroupCallState::new("CALL", creator());
    let mut initial = update(15, vec![participant("100001", "connected", 0)]);
    initial.relay = Some(relay_tx(1));
    assert_eq!(
      state.apply_update(initial.clone()),
      GroupStateApply::Applied
    );
    let mut older_roster = update(13, vec![participant("100001", "invited", 0)]);
    older_roster.relay = Some(relay_tx(2));
    assert_eq!(state.apply_update(older_roster), GroupStateApply::Applied);
    let current = state.snapshot().unwrap();
    assert_eq!(current.transaction_id, 15);
    assert_eq!(current.participants, initial.participants);
    assert_eq!(current.relay, Some(relay_tx(2)));
    let mut newer_roster = update(16, initial.participants.clone());
    newer_roster.relay = Some(relay_tx(1));
    assert_eq!(state.apply_update(newer_roster), GroupStateApply::Applied);
    let current = state.snapshot().unwrap();
    assert_eq!(current.transaction_id, 16);
    assert_eq!(
      current.relay,
      Some(relay_tx(2)),
      "roster progress cannot roll relay allocation backwards"
    );
  }

  #[test]
  fn late_relay_cannot_bypass_an_established_group_identity() {
    for transaction_id in [13, 15, 16] {
      let mut state = GroupCallState::new("CALL", creator());
      let mut current = update(15, vec![participant("100001", "connected", 0)]);
      current.group_jid = Some(Jid::new("100001-200002", Server::Group));
      assert_eq!(
        state.apply_update(current.clone()),
        GroupStateApply::Applied
      );
      let mut conflicting = update(transaction_id, current.participants.clone());
      conflicting.group_jid = Some(Jid::new("300003-400004", Server::Group));
      conflicting.relay = Some(relay_tx(1));
      assert_eq!(
        state.apply_update(conflicting),
        GroupStateApply::IdentityMismatch
      );
      assert_eq!(
        state.snapshot(),
        Some(&current),
        "rejection is mutation-free"
      );

      let mut matching = update(transaction_id, current.participants.clone());
      matching.relay = Some(relay_tx(1));
      assert_eq!(state.apply_update(matching), GroupStateApply::Applied);
      let committed = state.snapshot().expect("snapshot");
      assert_eq!(committed.transaction_id, transaction_id.max(15));
      assert_eq!(committed.group_jid, current.group_jid);
      assert_eq!(committed.participants, current.participants);
      assert_eq!(committed.relay, Some(relay_tx(1)));
    }
  }

  #[test]
  fn restored_pid_collisions_do_not_consume_transactions_or_controls() {
    for pid in [0, 1] {
      let mut state = GroupCallState::new("CALL", creator());
      let current = update(1, vec![participant("100001", "connected", pid)]);
      assert_eq!(
        state.apply_update(current.clone()),
        GroupStateApply::Applied
      );
      let hand = current.participants[0].jid.clone();
      state.set_raised_hand(&hand, true);
      let share = ScreenShare {
        state: ScreenShareState::Started,
        version: 2,
        screen_share_id: Some(7),
      };
      state.set_screen_share(&hand, share.clone());
      let mut collision = update(
        2,
        vec![
          without_pid(participant("100001", "connected", pid)),
          participant("200002", "connected", pid),
        ],
      );
      collision.media = "audio".to_string();
      collision.relay = Some(relay_tx(9));
      assert_eq!(
        state.apply_update(collision),
        GroupStateApply::InvalidSnapshot
      );
      assert_eq!(state.snapshot(), Some(&current));
      assert!(state.raised_hands().contains(&hand));
      assert_eq!(state.screen_shares().get(&hand), Some(&share));

      let corrected = update(
        2,
        vec![
          without_pid(participant("100001", "connected", pid)),
          participant("200002", "connected", pid + 2),
        ],
      );
      assert_eq!(state.apply_update(corrected), GroupStateApply::Applied);
      assert_eq!(
        state.snapshot().expect("snapshot").participants[0].devices[0].pid,
        Some(pid)
      );
      assert!(validate_group_snapshot_for_media(state.snapshot().expect("snapshot")).is_ok());
    }
  }

  #[test]
  fn pid_restoration_uses_only_explicit_pn_lid_device_mapping() {
    let lid = Jid::new("200002", Server::Lid);
    let pn = Jid::new("15550002002", Server::Pn);
    for (old_identity, new_identity) in [(&lid, &pn), (&pn, &lid)] {
      let mut state = GroupCallState::new("CALL", creator());
      let mut old = participant("200002", "connected", 0);
      old.pn = Some(pn.clone());
      old.devices[0].jid = old_identity.with_device(1);
      assert_eq!(
        state.apply_update(update(1, vec![old])),
        GroupStateApply::Applied
      );
      let mut new = without_pid(participant("200002", "connected", 0));
      new.pn = Some(pn.clone());
      new.devices[0].jid = new_identity.with_device(1);
      assert_eq!(
        state.apply_update(update(2, vec![new.clone()])),
        GroupStateApply::Applied
      );
      assert_eq!(
        state.snapshot().expect("snapshot").participants[0].devices[0].pid,
        Some(0)
      );
      assert_eq!(
        state.snapshot().expect("snapshot").participants[0].devices[0].jid,
        new.devices[0].jid,
        "PID continuity must not rewrite the media crypto namespace"
      );

      new.devices[0].jid = new_identity.with_device(2);
      assert_eq!(
        state.apply_update(update(3, vec![new])),
        GroupStateApply::Applied
      );
      assert_eq!(
        state.snapshot().expect("snapshot").participants[0].devices[0].pid,
        None,
        "a sibling device cannot inherit the other device's PID"
      );
    }
    let mut state = GroupCallState::new("CALL", creator());
    assert_eq!(
      state.apply_update(update(1, vec![participant("200002", "connected", 0)])),
      GroupStateApply::Applied
    );
    let mut unrelated = without_pid(participant("200002", "connected", 0));
    unrelated.jid = Jid::new("200002", Server::Pn);
    unrelated.devices[0].jid = unrelated.jid.with_device(1);
    assert_eq!(
      state.apply_update(update(2, vec![unrelated])),
      GroupStateApply::Applied
    );
    assert_eq!(
      state.snapshot().expect("snapshot").participants[0].devices[0].pid,
      None,
      "equal user text in different namespaces is not an identity mapping"
    );
  }

  #[test]
  fn pid_restoration_prefers_explicit_namespace_pids_over_aliases() {
    for reverse in [false, true] {
      let mut owner = participant("100001", "connected", 0);
      owner.pn = Some(Jid::new("200002", Server::Pn));
      let lid_device = owner.devices[0].jid.clone();
      let mut pn_device = owner.devices[0].clone();
      pn_device.jid = Jid::new("200002", Server::Pn).with_device(lid_device.device);
      pn_device.pid = Some(1);
      let pn_jid = pn_device.jid.clone();
      owner.devices.push(pn_device);
      if reverse {
        owner.devices.reverse();
      }
      let mut state = GroupCallState::new("CALL", creator());
      assert_eq!(
        state.apply_update(update(1, vec![owner.clone()])),
        GroupStateApply::Applied
      );
      for device in &mut owner.devices {
        device.pid = None;
      }
      assert_eq!(
        state.apply_update(update(2, vec![owner])),
        GroupStateApply::Applied
      );
      let devices = &state.snapshot().unwrap().participants[0].devices;
      assert_eq!(
        devices
          .iter()
          .find(|device| device.jid == lid_device)
          .unwrap()
          .pid,
        Some(0)
      );
      assert_eq!(
        devices
          .iter()
          .find(|device| device.jid == pn_jid)
          .unwrap()
          .pid,
        Some(1)
      );
    }
  }

  #[test]
  fn pid_zero_is_a_valid_participant_id() {
    let mut state = GroupCallState::new("CALL", creator());
    assert_eq!(
      state.apply_update(update(
        1,
        vec![
          participant("100001", "connected", 0),
          participant("200002", "connected", 1),
        ],
      )),
      GroupStateApply::Applied,
      "the call creator is pid 0 on live calls"
    );
    assert_eq!(
      state.apply_update(update(
        2,
        vec![
          participant("100001", "connected", 0),
          participant("200002", "connected", 0),
        ],
      )),
      GroupStateApply::InvalidSnapshot,
      "pids stay unique"
    );
  }

  #[test]
  fn roster_updates_without_pids_keep_the_known_pids() {
    let mut state = GroupCallState::new("CALL", creator());
    assert_eq!(
      state.apply_update(update(
        1,
        vec![
          participant("100001", "connected", 0),
          participant("200002", "connected", 1),
        ],
      )),
      GroupStateApply::Applied
    );
    assert_eq!(
      state.apply_update(update(
        2,
        vec![
          without_pid(participant("100001", "connected", 0)),
          without_pid(participant("200002", "connected", 1)),
          without_pid(participant("300003", "invited", 9)),
        ],
      )),
      GroupStateApply::Applied
    );
    let pids: Vec<_> = state
      .snapshot()
      .expect("snapshot")
      .participants
      .iter()
      .map(|participant| participant.devices[0].pid)
      .collect();
    assert_eq!(
      pids,
      vec![Some(0), Some(1), None],
      "absent pids mean unchanged; a device never seen with a pid stays pid-less"
    );
  }

  #[test]
  fn roster_only_updates_retain_group_identity_and_reject_retagging() {
    let mut state = GroupCallState::new("CALL", creator());
    let group_jid = Jid::new("1234567890-1111111111", Server::Group);
    let mut admitted = update(1, vec![participant("100001", "connected", 1)]);
    admitted.group_jid = Some(group_jid.clone());
    assert_eq!(state.apply_update(admitted), GroupStateApply::Applied);

    assert_eq!(
      state.apply_update(update(2, vec![participant("100001", "connected", 1)],)),
      GroupStateApply::Applied
    );
    assert_eq!(
      state
        .snapshot()
        .and_then(|snapshot| snapshot.group_jid.as_ref()),
      Some(&group_jid),
      "an omitted group_jid is a roster-only update, not an identity change"
    );

    let mut conflicting = update(3, vec![participant("100001", "connected", 1)]);
    conflicting.group_jid = Some(Jid::new("9876543210-2222222222", Server::Group));
    assert_eq!(
      state.apply_update(conflicting),
      GroupStateApply::IdentityMismatch
    );
    assert_eq!(
      state
        .snapshot()
        .map(|snapshot| (snapshot.transaction_id, snapshot.group_jid.as_ref())),
      Some((2, Some(&group_jid))),
      "a conflicting group_jid must not consume the transaction or retag the call"
    );
  }

  #[test]
  fn invalid_identity_duplicate_pid_device_and_oversized_limit_are_rejected() {
    let mut state = GroupCallState::new("CALL", creator());
    let mut wrong = update(1, vec![participant("100001", "connected", 1)]);
    wrong.call_id = "OTHER".to_string();
    assert_eq!(state.apply_update(wrong), GroupStateApply::IdentityMismatch);

    let duplicate_pid = update(
      1,
      vec![
        participant("100001", "connected", 1),
        participant("200002", "connected", 1),
      ],
    );
    assert_eq!(
      state.apply_update(duplicate_pid),
      GroupStateApply::InvalidSnapshot
    );

    let mut second = participant("200002", "connected", 2);
    second.devices[0].jid = Jid::new("100001", Server::Lid).with_device(1);
    let duplicate_device = update(1, vec![participant("100001", "connected", 1), second]);
    assert_eq!(
      state.apply_update(duplicate_device),
      GroupStateApply::InvalidSnapshot,
      "one device identity cannot belong to two roster participants"
    );

    let shared_alias = Jid::new("12025550111", Server::Pn);
    let mut first = participant("100001", "connected", 1);
    first.pn = Some(shared_alias.clone());
    let mut second = participant("200002", "connected", 2);
    second.pn = Some(shared_alias);
    assert_eq!(
      state.apply_update(update(1, vec![first, second])),
      GroupStateApply::InvalidSnapshot,
      "one PN alias cannot resolve to two canonical participants"
    );

    let canonical_pn = Jid::new("12025550112", Server::Pn);
    let mut aliased = participant("100001", "connected", 1);
    aliased.pn = Some(canonical_pn.clone());
    let mut canonical = participant("200002", "connected", 2);
    canonical.jid = canonical_pn;
    assert_eq!(
      state.apply_update(update(1, vec![aliased, canonical])),
      GroupStateApply::InvalidSnapshot,
      "a PN alias cannot collide with another participant's canonical identity"
    );

    let mut oversized = update(1, vec![]);
    oversized.connected_limit = 33;
    assert_eq!(
      state.apply_update(oversized),
      GroupStateApply::InvalidSnapshot
    );

    let mut over_connected_limit = update(
      1,
      vec![
        participant("100001", "connected", 1),
        participant("200002", "connected", 2),
      ],
    );
    over_connected_limit.connected_limit = 1;
    assert_eq!(
      state.apply_update(over_connected_limit),
      GroupStateApply::InvalidSnapshot,
      "the authoritative roster cannot already exceed its declared connected limit"
    );

    let mut device_fanout = participant("100001", "connected", 1);
    device_fanout.devices = (1..=GROUP_CALL_MAX_PARTICIPANTS + 1)
      .map(|index| GroupCallDevice {
        jid: Jid::new(format!("200{index:03}"), Server::Lid).with_device(1),
        platform: Some("web".to_string()),
        pid: Some(index as u32),
        capability_version: None,
        capability: Vec::new(),
      })
      .collect();
    assert_eq!(
      state.apply_update(update(1, vec![device_fanout])),
      GroupStateApply::InvalidSnapshot,
      "one connected user cannot expand the active media registry past the call limit"
    );
  }

  /// The snapshot an initial `offer` ack carries names the roster the call service accepted
  /// before any roster transaction exists, and declares no connected limit. It is admitted as
  /// the first snapshot of the call it answers, where a roster the service has already ordered
  /// and wrote the same zeros on stays malformed.
  #[test]
  fn a_partial_offer_ack_is_admitted_as_the_first_snapshot() {
    let partial = |transaction_id: u32, limit: u32| {
      let mut update = update(transaction_id, vec![participant("100001", "connected", 1)]);
      update.connected_limit = limit;
      update
    };
    let mut state = GroupCallState::new("CALL", creator());
    assert_eq!(
      state.apply_update(partial(0, 0)),
      GroupStateApply::InvalidSnapshot,
      "an ordered roster must state both update-plane integers"
    );
    assert!(state.snapshot().is_none());

    assert_eq!(
      state.apply_initial_offer_ack(partial(0, 0)),
      GroupStateApply::Applied
    );
    assert_eq!(
      state
        .snapshot()
        .map(|snapshot| (snapshot.transaction_id, snapshot.connected_limit)),
      Some((0, 0)),
      "the ack's roster is held as the call's snapshot, with no update-plane state claimed"
    );
    assert_eq!(
      state.snapshot().map(|snapshot| snapshot.participants.len()),
      Some(1),
      "the ack's roster is committed, not a placeholder"
    );

    // The first roster the service orders still advances the call past the partial snapshot.
    assert_eq!(
      state.apply_update(update(1, vec![participant("100001", "connected", 1)])),
      GroupStateApply::Applied
    );
    assert_eq!(
      state.snapshot().map(|snapshot| snapshot.transaction_id),
      Some(1)
    );
  }

  /// The ack's relaxation is bounded to the one snapshot it is: once a call holds a roster, a
  /// partial one is no longer an ack being admitted but a roster being claimed, so it is
  /// refused through the ordinary path — and the ack path reports it as overtaken instead of
  /// letting its missing integers decide anything.
  #[test]
  fn only_the_first_snapshot_may_be_the_partial_offer_ack() {
    let mut state = GroupCallState::new("CALL", creator());
    assert_eq!(
      state.apply_initial_offer_ack(update(5, vec![])),
      GroupStateApply::Applied
    );

    let mut partial = update(6, vec![participant("100001", "connected", 1)]);
    partial.connected_limit = 0;
    assert_eq!(
      state.apply_initial_offer_ack(partial.clone()),
      GroupStateApply::Stale,
      "a late partial ack is superseded by the roster already ordered"
    );
    assert_eq!(
      state.apply_update(partial),
      GroupStateApply::InvalidSnapshot,
      "the ordinary path still refuses it as malformed"
    );
    assert_eq!(
      state.snapshot().map(|snapshot| snapshot.transaction_id),
      Some(5),
      "neither refusal consumed a transaction or replaced the roster"
    );
  }

  /// A group update overtaking the ack is an outcome the offer path is written for, so the
  /// overtaken ack must not fail it: it reports stale, and the roster — including a relay
  /// allocation the newer update brought — stays exactly as the service ordered it.
  #[test]
  fn a_partial_ack_overtaken_by_an_ordered_roster_is_stale_and_changes_nothing() {
    let mut state = GroupCallState::new("CALL", creator());
    let mut ordered = update(
      3,
      vec![
        participant("100001", "connected", 1),
        participant("200002", "connected", 2),
      ],
    );
    ordered.relay = Some(relay_tx(11));
    ordered.group_jid = Some(Jid::new("100001-200002", Server::Group));
    assert_eq!(state.apply_update(ordered), GroupStateApply::Applied);

    let mut late_ack = update(0, vec![participant("100001", "connected", 1)]);
    late_ack.connected_limit = 0;
    assert_eq!(
      state.apply_initial_offer_ack(late_ack),
      GroupStateApply::Stale,
      "the offer path accepts stale, so the call continues on the roster it holds"
    );
    let held = state.snapshot().expect("the ordered roster is still held");
    assert_eq!(
      held.transaction_id, 3,
      "the overtaken ack did not replace the roster"
    );
    assert_eq!(
      held.participants.len(),
      2,
      "the overtaken ack did not shrink the roster"
    );
    assert_eq!(
      held.relay.as_ref().and_then(|relay| relay.transaction_id),
      Some(11),
      "the newer relay allocation survived the overtaken ack"
    );

    // A foreign ack is still refused on identity, never reported as merely late.
    let mut foreign = update(0, vec![]);
    foreign.connected_limit = 0;
    foreign.call_creator = Jid::new("999999", Server::Lid);
    assert_eq!(
      state.apply_initial_offer_ack(foreign),
      GroupStateApply::IdentityMismatch
    );

    // …and so is one that names a different group: the late report must not outrank the
    // identity the roster already holds, because the offer path accepts `Stale` and would
    // keep its held snapshot beside another group's ack.
    let mut foreign_group = update(0, vec![participant("100001", "connected", 1)]);
    foreign_group.connected_limit = 0;
    foreign_group.group_jid = Some(Jid::new("5555555555-6666666666", Server::Group));
    assert_eq!(
      state.apply_initial_offer_ack(foreign_group),
      GroupStateApply::IdentityMismatch
    );

    // An ack that states no group, or the held group itself, is still just late.
    let mut same_group = update(0, vec![participant("100001", "connected", 1)]);
    same_group.connected_limit = 0;
    same_group.group_jid = Some(Jid::new("100001-200002", Server::Group));
    assert_eq!(
      state.apply_initial_offer_ack(same_group),
      GroupStateApply::Stale
    );
    let mut no_group = update(0, vec![participant("100001", "connected", 1)]);
    no_group.connected_limit = 0;
    assert_eq!(
      state.apply_initial_offer_ack(no_group),
      GroupStateApply::Stale
    );
  }

  /// The ack is excused the two integers and nothing else: a failed declared limit, an unknown
  /// media mode, and a foreign identity are all still refusals, and none of them commits.
  #[test]
  fn a_partial_offer_ack_still_answers_to_every_other_roster_rule() {
    let mut state = GroupCallState::new("CALL", creator());

    let mut unknown_media = update(0, vec![]);
    unknown_media.connected_limit = 0;
    unknown_media.media = "text".to_string();
    assert_eq!(
      state.apply_initial_offer_ack(unknown_media),
      GroupStateApply::InvalidSnapshot
    );

    let mut over_limit = update(
      0,
      vec![
        participant("100001", "connected", 1),
        participant("200002", "connected", 2),
      ],
    );
    over_limit.connected_limit = 1;
    assert_eq!(
      state.apply_initial_offer_ack(over_limit),
      GroupStateApply::InvalidSnapshot,
      "a limit the ack does declare still bounds the roster it names"
    );

    let mut oversized = update(0, vec![]);
    oversized.connected_limit = GROUP_CALL_MAX_PARTICIPANTS as u32 + 1;
    assert_eq!(
      state.apply_initial_offer_ack(oversized),
      GroupStateApply::InvalidSnapshot
    );

    let mut foreign = update(0, vec![]);
    foreign.connected_limit = 0;
    foreign.call_creator = Jid::new("999999", Server::Lid);
    assert_eq!(
      state.apply_initial_offer_ack(foreign),
      GroupStateApply::IdentityMismatch
    );
    assert!(state.snapshot().is_none(), "nothing partial was committed");
  }

  /// A rekey the ack asks for rides nowhere on the wire — transaction zero cannot name a
  /// fan-out transaction — so it is parked when the ack is admitted and taken exactly once:
  /// a rejected ack parks nothing, a quiet ack parks nothing, and committing the answering
  /// roster (which goes through this very function again) does not clear its own request.
  #[test]
  fn an_admitted_partial_ack_parks_its_rekey_request() {
    let requesting_ack = || {
      let mut ack = update(0, vec![participant("100001", "connected", 1)]);
      ack.connected_limit = 0;
      ack.rekey_requested = true;
      ack
    };

    let mut state = GroupCallState::new("CALL", creator());
    assert_eq!(
      state.apply_initial_offer_ack(requesting_ack()),
      GroupStateApply::Applied
    );
    assert!(
      state.take_owed_rekey(),
      "the admitted ack's request is parked and available"
    );
    assert!(!state.take_owed_rekey(), "and taken exactly once");

    let mut state = GroupCallState::new("CALL", creator());
    let mut rejected = requesting_ack();
    rejected.media = "text".to_string();
    assert_eq!(
      state.apply_initial_offer_ack(rejected),
      GroupStateApply::InvalidSnapshot
    );
    assert!(
      !state.take_owed_rekey(),
      "an unadmitted ack cannot owe a key"
    );

    let mut state = GroupCallState::new("CALL", creator());
    let mut quiet = update(0, vec![]);
    quiet.connected_limit = 0;
    assert_eq!(
      state.apply_initial_offer_ack(quiet),
      GroupStateApply::Applied
    );
    assert!(!state.take_owed_rekey(), "nothing was requested");

    let mut state = GroupCallState::new("CALL", creator());
    assert_eq!(
      state.apply_initial_offer_ack(requesting_ack()),
      GroupStateApply::Applied
    );
    assert_eq!(
      state.apply_update(update(1, vec![participant("100001", "connected", 1)])),
      GroupStateApply::Applied,
      "the first ordered roster commits"
    );
    assert!(
      state.take_owed_rekey(),
      "committing the answering roster leaves its own request for the caller to take"
    );
  }

  /// A roster entry's own error code is not call state and is never folded into it: it is
  /// committed with the roster it arrived on, untouched, beside the call's own transaction.
  #[test]
  fn a_participant_error_rides_with_the_snapshot_it_arrived_on() {
    let mut state = GroupCallState::new("CALL", creator());
    let mut roster = update(1, vec![participant("100001", "connected", 1)]);
    roster.participants[0].error = Some(487);

    assert_eq!(state.apply_update(roster), GroupStateApply::Applied);
    let snapshot = state.snapshot().expect("the roster was committed");
    assert_eq!(
      snapshot.transaction_id, 1,
      "the call's own status is the roster's transaction"
    );
    assert_eq!(
      snapshot.participants[0].error,
      Some(487),
      "the participant's failure survives admission separately"
    );
  }

  #[test]
  fn roster_devices_must_belong_to_their_enclosing_participant() {
    let mut state = GroupCallState::new("CALL", creator());
    let mut mismatched = participant("100001", "connected", 1);
    mismatched.devices[0].jid = Jid::new("200002", Server::Lid).with_device(1);
    assert_eq!(
      state.apply_update(update(1, vec![mismatched])),
      GroupStateApply::InvalidSnapshot,
      "a device cannot be attributed to an unrelated canonical participant"
    );

    let mut aliased = participant("100001", "connected", 1);
    let pn = Jid::new("12025550113", Server::Pn);
    aliased.pn = Some(pn.clone());
    aliased.devices[0].jid = pn.with_device(2);
    assert_eq!(
      state.apply_update(update(1, vec![aliased])),
      GroupStateApply::Applied,
      "a device matching the participant's explicit PN alias remains valid"
    );
  }

  #[test]
  fn route_collisions_do_not_consume_the_roster_transaction() {
    let mut state = GroupCallState::new("CALL", creator());
    let first = "37774";
    let second = "53838";
    let first_id =
      format_e2e_srtp_participant_id(&Jid::new(first, Server::Lid).with_device(1).to_string());
    let second_id =
      format_e2e_srtp_participant_id(&Jid::new(second, Server::Lid).with_device(1).to_string());
    assert_eq!(
      derive_wasm_participant_ssrc("CALL", &first_id, 0),
      derive_wasm_participant_ssrc("CALL", &second_id, 0),
      "fixture must collide in the audio route"
    );

    assert_eq!(
      state.apply_update(update(
        1,
        vec![
          participant(first, "connected", 1),
          participant(second, "connected", 2),
        ],
      )),
      GroupStateApply::InvalidSnapshot
    );
    assert_eq!(
      state.apply_update(update(1, vec![participant(first, "connected", 1)])),
      GroupStateApply::Applied,
      "a corrected redelivery must retain the rejected transaction ID"
    );
  }

  #[test]
  fn stopped_screen_share_and_lowered_hand_remove_state() {
    let mut state = GroupCallState::new("CALL", creator());
    let alice = Jid::new("200002", Server::Lid).with_device(3);
    state.set_raised_hand(&alice, true);
    state.set_screen_share(
      &alice,
      ScreenShare {
        state: ScreenShareState::Started,
        version: 2,
        screen_share_id: Some(9),
      },
    );
    assert_eq!(state.raised_hands().len(), 1);
    assert_eq!(state.screen_shares().len(), 1);

    state.set_raised_hand(&alice, false);
    state.set_screen_share(
      &alice,
      ScreenShare {
        state: ScreenShareState::Stopped,
        version: 2,
        screen_share_id: None,
      },
    );
    assert!(state.raised_hands().is_empty());
    assert!(state.screen_shares().is_empty());
  }

  #[test]
  fn waiting_room_identity_and_transaction_order_are_enforced() {
    let mut state = GroupCallState::new("CALL", creator());
    assert_eq!(
      state.apply_waiting_room(waiting_room(Some(4))),
      GroupStateApply::Applied
    );
    assert_eq!(
      state.apply_waiting_room(waiting_room(Some(3))),
      GroupStateApply::Stale
    );
    assert_eq!(
      state.apply_waiting_room(waiting_room(None)),
      GroupStateApply::Applied,
      "transaction-less service updates always apply"
    );
    assert_eq!(
      state.apply_waiting_room(waiting_room(Some(3))),
      GroupStateApply::Stale,
      "transaction-less updates must not erase the numbered watermark"
    );

    let mut wrong_call = waiting_room(Some(5));
    wrong_call.call_id = "OTHER".to_string();
    assert_eq!(
      state.apply_waiting_room(wrong_call),
      GroupStateApply::IdentityMismatch
    );
    let mut wrong_creator = waiting_room(Some(5));
    wrong_creator.call_creator = Jid::new("999999", Server::Lid);
    assert_eq!(
      state.apply_waiting_room(wrong_creator),
      GroupStateApply::IdentityMismatch
    );
    let mut wrong_link = waiting_room(Some(5));
    wrong_link.link_token = "OTHER-CALL-LINK".to_string();
    assert_eq!(
      state.apply_waiting_room(wrong_link),
      GroupStateApply::IdentityMismatch
    );
    let mut wrong_media = waiting_room(Some(5));
    wrong_media.media = crate::types::group_call::CallLinkMedia::Video;
    assert_eq!(
      state.apply_waiting_room(wrong_media),
      GroupStateApply::IdentityMismatch
    );
    assert_eq!(
      state.apply_waiting_room(waiting_room(Some(5))),
      GroupStateApply::Applied,
      "conflicting link identities must not consume the transaction watermark"
    );
  }

  #[test]
  fn pn_alias_controls_are_canonicalized_to_the_current_roster_jid() {
    let mut state = GroupCallState::new("CALL", creator());
    let mut alice = participant("200002", "connected", 2);
    let alice_jid = alice.jid.clone();
    let alice_pn = Jid::new("12025550111", Server::Pn);
    alice.pn = Some(alice_pn.clone());
    let mut initial_alice = alice.clone();
    initial_alice.jid = alice_pn.clone();
    initial_alice.pn = None;
    initial_alice.devices[0].jid = alice_pn.clone().with_device(2);
    assert_eq!(
      state.apply_update(update(
        1,
        vec![participant("100001", "connected", 1), initial_alice],
      )),
      GroupStateApply::Applied
    );
    state.set_raised_hand(&alice_pn, true);
    state.set_screen_share(
      &alice_pn,
      ScreenShare {
        state: ScreenShareState::Started,
        version: 2,
        screen_share_id: Some(7),
      },
    );

    assert_eq!(
      state.apply_update(update(
        2,
        vec![participant("100001", "connected", 1), alice],
      )),
      GroupStateApply::Applied
    );
    assert!(state.raised_hands().contains(&alice_jid));
    assert!(!state.raised_hands().contains(&alice_pn));
    assert!(state.screen_shares().contains_key(&alice_jid));
    assert!(!state.screen_shares().contains_key(&alice_pn));
  }
}
