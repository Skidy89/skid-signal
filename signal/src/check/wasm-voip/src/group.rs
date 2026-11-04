// velowa (https://github.com/7ucg/velowa) (c) 2026 Baron. Copying any part of this file, however small, requires credit: see LICENSE.
//! Group calls: the call-scoped offer, the server's authoritative roster/relay snapshots, the shared epoch key and the
//! group mode of the call engine. JavaScript does the signalling I/O and the Signal encryption of the epoch; this
//! module builds and reads the stanzas and keeps the transaction-ordered roster.

use wacore_binary::Jid;
use wacore_voip::stanza::call::OfferDeviceKey;
use wacore_voip::stanza::group_call::{
    parse_group_invite_snapshot,
    GroupEncRekeyParams, InitialGroupOfferParams, build_group_enc_rekey, build_initial_group_offer,
    parse_group_enc_rekey, parse_group_update, parse_initial_group_call_ack,
};
use wacore_voip::types::group_call::{GroupCallDevice, GroupCallParticipant, GroupCallUpdate};
use wacore_voip::voip::{
    AudioConfig, AudioFormat, CallConfig, CallDirection, CallEngine as CoreCallEngine,
    GroupEngineConfig,
};
use wacore_voip::voip_control::group::{GroupCallState, GroupStateApply};
use wasm_bindgen::prelude::*;

use crate::{CallEngine, RngTxIds, node_to_js_value, unpack_node};

fn err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

fn jid(s: &str) -> Result<Jid, JsValue> {
    s.parse().map_err(|_| err(format!("invalid JID: {s}")))
}

#[derive(serde::Deserialize)]
struct DeviceJson {
    jid: String,
    #[serde(default)]
    capability: Vec<u8>,
}

#[derive(serde::Deserialize)]
struct ParticipantJson {
    jid: String,
    devices: Vec<DeviceJson>,
}

#[derive(serde::Deserialize)]
struct OfferJson {
    call_id: String,
    id: String,
    creator: String,
    #[serde(default)]
    group_jid: Option<String>,
    participants: Vec<ParticipantJson>,
    #[serde(default = "default_rate")]
    audio_rate: u32,
    #[serde(default)]
    video: bool,
}

fn default_rate() -> u32 {
    16_000
}

/// Build the call-scoped offer of an ad-hoc or group-bound group call (a plain node object for `sendNode`).
#[wasm_bindgen(js_name = buildGroupOffer)]
pub fn build_group_offer(params_json: &str) -> Result<JsValue, JsValue> {
    let p: OfferJson = serde_json::from_str(params_json).map_err(err)?;
    let creator = jid(&p.creator)?;
    let group = p.group_jid.as_deref().map(jid).transpose()?;
    let mut participants = Vec::with_capacity(p.participants.len());
    for u in &p.participants {
        let mut devices = Vec::with_capacity(u.devices.len());
        for d in &u.devices {
            let mut dev = GroupCallDevice::new(jid(&d.jid)?);
            if !d.capability.is_empty() {
                dev = dev.with_capability(1, d.capability.clone());
            }
            devices.push(dev);
        }
        participants.push(GroupCallParticipant::new(jid(&u.jid)?, devices));
    }
    let node = build_initial_group_offer(&InitialGroupOfferParams {
        call_id: &p.call_id,
        id: &p.id,
        call_creator: &creator,
        group_jid: group.as_ref(),
        participants: &participants,
        audio_rate: p.audio_rate,
        video: p.video,
    })
    .map_err(err)?;
    Ok(node_to_js_value(&node))
}

#[derive(serde::Deserialize)]
struct RekeyJson {
    call_id: String,
    id: String,
    to: String,
    creator: String,
    transaction_id: u32,
    enc_type: String,
    ciphertext: Vec<u8>,
    #[serde(default)]
    device_identity: Option<Vec<u8>>,
}

/// One direct delivery of the shared epoch to a device (`<enc_rekey>`), as a plain node object.
#[wasm_bindgen(js_name = buildGroupEncRekey)]
pub fn build_group_enc_rekey_js(params_json: &str) -> Result<JsValue, JsValue> {
    let p: RekeyJson = serde_json::from_str(params_json).map_err(err)?;
    let to = jid(&p.to)?;
    let creator = jid(&p.creator)?;
    let key = OfferDeviceKey {
        device_jid: to.clone(),
        ciphertext: p.ciphertext,
        enc_type: p.enc_type,
    };
    let node = build_group_enc_rekey(&GroupEncRekeyParams {
        call_id: &p.call_id,
        id: &p.id,
        to: &to,
        call_creator: &creator,
        transaction_id: p.transaction_id,
        device_key: &key,
        device_identity: p.device_identity.as_deref(),
    })
    .map_err(err)?;
    Ok(node_to_js_value(&node))
}

/// Read an incoming `<enc_rekey>`: `{call_id, call_creator, transaction_id, enc_type, ciphertext}`.
#[wasm_bindgen(js_name = parseGroupEncRekey)]
pub fn parse_group_enc_rekey_js(encoded_node: &[u8]) -> Result<JsValue, JsValue> {
    let (unpacked, _) = unpack_node(encoded_node)?;
    let node = wacore_binary::marshal::unmarshal_ref(&unpacked).map_err(err)?;
    let r = parse_group_enc_rekey(&node).map_err(err)?;
    #[derive(serde::Serialize)]
    struct Out {
        call_id: String,
        call_creator: String,
        transaction_id: u32,
        enc_type: String,
        ciphertext: Vec<u8>,
    }
    to_js(&Out {
        call_id: r.call_id,
        call_creator: r.call_creator.to_string(),
        transaction_id: r.transaction_id,
        enc_type: r.encryption_type,
        ciphertext: r.ciphertext,
    })
}

fn to_js<T: serde::Serialize>(v: &T) -> Result<JsValue, JsValue> {
    let json = serde_json::to_string(v).map_err(err)?;
    js_sys::JSON::parse(&json)
}

/// The roster the server holds for one group call, in the order its transactions say.
#[wasm_bindgen]
pub struct GroupSession {
    state: GroupCallState,
    call_id: String,
    creator: Jid,
    self_jid: Jid,
}

#[derive(serde::Serialize)]
struct Summary {
    applied: &'static str,
    transaction_id: u32,
    media: String,
    rekey_requested: bool,
    rekey_owed: bool,
    has_relay: bool,
    relay_endpoint: Option<(String, u16)>,
    /// Connected devices that already have a media id, other than ours: who must be sent the shared epoch.
    epoch_recipients: Vec<String>,
    /// Every user (no device) the roster names, whatever their state.
    members: Vec<String>,
    participants: serde_json::Value,
}

fn applied_name(a: &GroupStateApply) -> &'static str {
    match a {
        GroupStateApply::Applied => "applied",
        GroupStateApply::Stale => "stale",
        GroupStateApply::IdentityMismatch => "identity-mismatch",
        _ => "other",
    }
}

#[wasm_bindgen]
impl GroupSession {
    /// `self_jid` is our own device LID; `creator` the call creator's device LID.
    #[wasm_bindgen(constructor)]
    pub fn new(call_id: &str, creator: &str, self_jid: &str) -> Result<GroupSession, JsValue> {
        let creator = jid(creator)?;
        Ok(GroupSession {
            state: GroupCallState::new(call_id, creator.clone()),
            call_id: call_id.to_string(),
            creator,
            self_jid: jid(self_jid)?,
        })
    }

    fn summary(&mut self, applied: &GroupStateApply) -> Result<JsValue, JsValue> {
        let rekey_owed = self.state.take_owed_rekey();
        let snap = self.state.snapshot();
        let (transaction_id, media, rekey_requested, participants, relay_endpoint, has_relay, recipients) =
            match snap {
                Some(u) => (
                    u.transaction_id,
                    u.media.clone(),
                    u.rekey_requested,
                    serde_json::to_value(&u.participants).unwrap_or_default(),
                    u.relay.as_ref().and_then(|r| {
                        r.endpoints
                            .iter()
                            .find_map(|e| e.ipv4.clone().zip(e.port))
                    }),
                    u.relay.is_some(),
                    recipients(u, &self.self_jid),
                ),
                None => (0, String::new(), false, serde_json::Value::Null, None, false, vec![]),
            };
        let members: Vec<String> = self
            .state
            .snapshot()
            .map(|u| {
                u.participants
                    .iter()
                    .map(|p| {
                        let mut j = p.jid.clone();
                        j.device = 0;
                        j.to_string()
                    })
                    .collect()
            })
            .unwrap_or_default();
        to_js(&Summary {
            applied: applied_name(applied),
            transaction_id,
            media,
            rekey_requested,
            rekey_owed,
            has_relay,
            relay_endpoint,
            epoch_recipients: recipients,
            members,
            participants,
        })
    }

    /// The `<ack>` of our offer (or of a link join): the first roster and the shared relay.
    #[wasm_bindgen(js_name = applyAck)]
    pub fn apply_ack(&mut self, encoded_ack: &[u8]) -> Result<JsValue, JsValue> {
        let (unpacked, _) = unpack_node(encoded_ack)?;
        let node = wacore_binary::marshal::unmarshal_ref(&unpacked).map_err(err)?;
        let update = parse_initial_group_call_ack(&node)
            .map_err(err)?
            .ok_or_else(|| err("the ack has no group snapshot"))?;
        if update.call_id != self.call_id {
            return Err(err("ack belongs to another call"));
        }
        let applied = self.state.apply_initial_offer_ack(update);
        self.summary(&applied)
    }

    /// The `<offer>` of an invitation into a group call (its action node, encoded): the roster it carries, if any.
    #[wasm_bindgen(js_name = applyInvite)]
    pub fn apply_invite(&mut self, encoded_offer: &[u8]) -> Result<JsValue, JsValue> {
        let (unpacked, _) = unpack_node(encoded_offer)?;
        let node = wacore_binary::marshal::unmarshal_ref(&unpacked).map_err(err)?;
        match parse_group_invite_snapshot(&node).map_err(err)? {
            Some(update) => {
                if update.call_id != self.call_id {
                    return Err(err("offer belongs to another call"));
                }
                let applied = self.state.apply_initial_offer_ack(update);
                self.summary(&applied)
            }
            None => self.summary(&GroupStateApply::Stale),
        }
    }

    /// A `<group_update>` (the call stanza's action node, encoded).
    #[wasm_bindgen(js_name = applyUpdate)]
    pub fn apply_update(&mut self, encoded_action: &[u8]) -> Result<JsValue, JsValue> {
        let (unpacked, _) = unpack_node(encoded_action)?;
        let node = wacore_binary::marshal::unmarshal_ref(&unpacked).map_err(err)?;
        let update = parse_group_update(&node).map_err(err)?;
        let applied = self.state.apply_update(update);
        self.summary(&applied)
    }

    /// Build the group media engine from the relay snapshot. `opus` selects standard Opus (encoded I/O).
    #[wasm_bindgen(js_name = createEngine)]
    pub fn create_engine(
        &self,
        incoming: bool,
        opus: bool,
        video: bool,
    ) -> Result<CallEngine, JsValue> {
        let update = self
            .state
            .snapshot()
            .ok_or_else(|| err("no group snapshot yet"))?
            .clone();
        let relay = update.relay.as_ref().ok_or_else(|| err("the snapshot has no relay"))?;
        let direction = if incoming {
            CallDirection::Incoming
        } else {
            CallDirection::Outgoing
        };
        let mut cfg = CallConfig::for_group(
            direction,
            &self.call_id,
            &self.self_jid.to_string(),
            &self.creator.to_string(),
            relay,
        )
        .map_err(err)?;
        if opus {
            cfg.audio = AudioConfig::encoded(AudioFormat::OPUS_16KHZ_60MS);
        }
        cfg.enable_video = video;
        let mut engine =
            CoreCallEngine::new(cfg, Box::new(RngTxIds)).map_err(err)?;
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

    /// Hand the engine the roster the session holds now (after `applyUpdate`).
    #[wasm_bindgen(js_name = pushToEngine)]
    pub fn push_to_engine(&self, engine: &mut CallEngine, now: f64) -> Result<String, JsValue> {
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

/// Connected devices with a media id that are not us: the ones the shared epoch must be sent to.
fn recipients(update: &GroupCallUpdate, me: &Jid) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    update
        .participants
        .iter()
        .filter(|p| p.is_connected())
        .flat_map(|p| p.devices.iter())
        .filter(|d| d.pid.is_some() && !(d.jid.user == me.user && d.jid.device == me.device))
        .filter(|d| seen.insert(d.jid.to_string()))
        .map(|d| d.jid.to_string())
        .collect()
}
