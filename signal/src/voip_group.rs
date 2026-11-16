use crate::voip::{CallEngine, RandomTxIds};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use wacore_binary::{marshal::unmarshal_ref, util::unpack, Jid};
use wacore_voip::{
  stanza::group_call::{
    parse_group_invite_snapshot, parse_group_update, parse_initial_group_call_ack,
  },
  types::group_call::GroupCallUpdate,
  voip::{
    AudioConfig, AudioFormat, CallConfig, CallDirection, CallEngine as CoreCallEngine,
    GroupEngineConfig,
  },
  voip_control::group::{GroupCallState, GroupStateApply},
};

fn err(e: impl std::fmt::Display) -> napi::Error {
  napi::Error::from_reason(e.to_string())
}
fn jid(s: &str) -> napi::Result<Jid> {
  s.parse().map_err(err)
}

#[napi]
pub struct GroupSession {
  state: GroupCallState,
  call_id: String,
  creator: Jid,
  self_jid: Jid,
}

#[napi]
impl GroupSession {
  #[napi(constructor)]
  pub fn new(call_id: String, creator: String, self_jid: String) -> napi::Result<Self> {
    let creator = jid(&creator)?;
    Ok(Self {
      state: GroupCallState::new(&call_id, creator.clone()),
      call_id,
      creator,
      self_jid: jid(&self_jid)?,
    })
  }

  #[napi(js_name = applyAck)]
  pub fn apply_ack(&mut self, encoded: Buffer) -> napi::Result<String> {
    let bytes = unpack(&encoded).map_err(err)?;
    let node = unmarshal_ref(&bytes).map_err(err)?;
    let update = parse_initial_group_call_ack(&node)
      .map_err(err)?
      .ok_or_else(|| err("ack has no group snapshot"))?;
    if update.call_id != self.call_id {
      return Err(err("ack belongs to another call"));
    }
    let result = self.state.apply_initial_offer_ack(update);
    let name = match result {
      GroupStateApply::Applied => "applied",
      GroupStateApply::Stale => "stale",
      GroupStateApply::IdentityMismatch => "identity-mismatch",
      _ => "invalid",
    };
    self.summary(name)
  }

  #[napi(js_name = applyInvite)]
  pub fn apply_invite(&mut self, encoded: Buffer) -> napi::Result<String> {
    let bytes = unpack(&encoded).map_err(err)?;
    let node = unmarshal_ref(&bytes).map_err(err)?;
    match parse_group_invite_snapshot(&node).map_err(err)? {
      Some(update) => self.apply(update),
      None => self.summary("stale"),
    }
  }

  #[napi(js_name = applyUpdate)]
  pub fn apply_update(&mut self, encoded: Buffer) -> napi::Result<String> {
    let bytes = unpack(&encoded).map_err(err)?;
    let node = unmarshal_ref(&bytes).map_err(err)?;
    let update = parse_group_update(&node).map_err(err)?;
    self.apply(update)
  }

  fn apply(&mut self, update: GroupCallUpdate) -> napi::Result<String> {
    if update.call_id != self.call_id {
      return Err(err("snapshot belongs to another call"));
    }
    let result = self.state.apply_update(update);
    let name = match result {
      GroupStateApply::Applied => "applied",
      GroupStateApply::Stale => "stale",
      GroupStateApply::IdentityMismatch => "identity-mismatch",
      _ => "invalid",
    };
    self.summary(name)
  }

  fn summary(&self, applied: &str) -> napi::Result<String> {
    let snapshot = self.state.snapshot();
    let recipients: Vec<String> = snapshot
      .into_iter()
      .flat_map(|s| &s.participants)
      .filter(|p| p.is_connected())
      .flat_map(|p| &p.devices)
      .filter(|d| {
        d.pid.is_some()
          && !(d.jid.user == self.self_jid.user && d.jid.device == self.self_jid.device)
      })
      .map(|d| d.jid.to_string())
      .collect();
    let members: Vec<String> = snapshot
      .into_iter()
      .flat_map(|s| &s.participants)
      .map(|p| {
        let mut j = p.jid.clone();
        j.device = 0;
        j.to_string()
      })
      .collect();
    Ok(serde_json::json!({"applied": applied, "transactionId": snapshot.map_or(0, |s| s.transaction_id), "media": snapshot.map_or("", |s| s.media.as_str()), "rekeyRequested": snapshot.is_some_and(|s| s.rekey_requested), "hasRelay": snapshot.is_some_and(|s| s.relay.is_some()), "epochRecipients": recipients, "members": members, "participants": snapshot.map(|s| serde_json::to_value(&s.participants).unwrap_or_default())}).to_string())
  }

  #[napi(js_name = createEngine)]
  pub fn create_engine(&self, incoming: bool, opus: bool, video: bool) -> napi::Result<CallEngine> {
    let update = self
      .state
      .snapshot()
      .ok_or_else(|| err("no group snapshot yet"))?
      .clone();
    let relay = update
      .relay
      .as_ref()
      .ok_or_else(|| err("group snapshot has no relay"))?;
    let direction = if incoming {
      CallDirection::Incoming
    } else {
      CallDirection::Outgoing
    };
    let mut config = CallConfig::for_group(
      direction,
      &self.call_id,
      &self.self_jid.to_string(),
      &self.creator.to_string(),
      relay,
    )
    .map_err(err)?;
    if opus {
      config.audio = AudioConfig::encoded(AudioFormat::OPUS_16KHZ_60MS);
    }
    config.enable_video = video;
    let mut engine = CoreCallEngine::new(config, Box::new(RandomTxIds)).map_err(err)?;
    engine
      .configure_group(GroupEngineConfig {
        call_creator: self.creator.clone(),
        self_jid: self.self_jid.clone(),
        initial_update: update,
        direct_peer: None,
      })
      .map_err(err)?;
    Ok(CallEngine::from_core(engine))
  }

  #[napi(js_name = pushToEngine)]
  pub fn push_to_engine(&self, engine: &mut CallEngine, now: f64) -> napi::Result<String> {
    let update = self
      .state
      .snapshot()
      .ok_or_else(|| err("no group snapshot yet"))?;
    engine
      .core_mut()
      .apply_group_update(now as u64, update)
      .map(|r| format!("{r:?}"))
      .map_err(err)
  }
}
