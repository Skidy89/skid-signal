// velowa (https://github.com/7ucg/velowa) (c) 2026 Baron. Copying any part of this file, however small, requires credit: see LICENSE.
//! wasm-bindgen bridge for the vendored call stack. It owns no socket and no clock: JavaScript feeds relay datagrams,
//! microphone frames and timer ticks in, and drains the engine's outputs (datagrams to send, PCM to play, events).

mod group;
mod relay;

use wacore_voip::voip::{
    AudioConfig, AudioFormat, CallConfig, CallDirection, CallEngine as CoreCallEngine, CallEvent, Input, NEVER,
    Output, TxIdSource,
};
use wacore_voip::voip_control::relay_parse;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

fn to_js_object<T: serde::Serialize + ?Sized>(value: &T) -> Result<JsValue, JsValue> {
    let serializer = serde_wasm_bindgen_like::Serializer;
    serializer.to_js(value)
}

/// Minimal serde -> JS object serializer built on JSON (plain objects, byte arrays as number arrays).
mod serde_wasm_bindgen_like {
    use wasm_bindgen::JsValue;
    pub struct Serializer;
    impl Serializer {
        pub fn to_js<T: serde::Serialize + ?Sized>(&self, value: &T) -> Result<JsValue, JsValue> {
            let json = serde_json::to_string(value).map_err(|e| JsValue::from_str(&e.to_string()))?;
            js_sys::JSON::parse(&json)
        }
    }
}

/// Parse the `<relay>` block of an encoded `<ack>` (or `<offer>`-carrying) node and return what the engine needs to
/// allocate the media relay: `relay_ip`, `relay_port`, `relay_token`, `auth_token`, `integrity_key`, `warp_mi_tag_len`.
#[wasm_bindgen(js_name = parseRelayFromNode)]
pub fn parse_relay_from_node(encoded_node: &[u8]) -> Result<JsValue, JsValue> {
    let unpacked = wacore_binary::util::unpack(encoded_node)
        .map_err(|e| JsValue::from_str(&format!("unpack error: {e}")))?;
    let node = wacore_binary::marshal::unmarshal_ref(&unpacked)
        .map_err(|e| JsValue::from_str(&format!("decode error: {e}")))?;
    let relay_data = relay_parse::parse_relay_data_from_ack(&node)
        .ok_or_else(|| JsValue::from_str("no <relay> child on this node"))?;
    let endpoint = relay_parse::get_media_relay_endpoint(&relay_data)
        .ok_or_else(|| JsValue::from_str("relay has no usable media endpoint"))?;
    let (relay_ip, relay_port) = relay_parse::get_primary_ipv4_address(endpoint)
        .ok_or_else(|| JsValue::from_str("relay endpoint has no IPv4 address"))?;
    let relay_token = relay_data
        .relay_tokens
        .get(endpoint.token_id as usize)
        .filter(|t| !t.is_empty())
        .cloned()
        .ok_or_else(|| JsValue::from_str("relay has no token for this endpoint"))?;
    let auth_token = relay_data
        .auth_tokens
        .get(endpoint.auth_token_id as usize)
        .filter(|t| !t.is_empty())
        .cloned()
        .unwrap_or_default();
    let integrity_key = relay_data
        .relay_key_ascii
        .clone()
        .ok_or_else(|| JsValue::from_str("relay has no <key> (STUN integrity key)"))?;
    #[derive(serde::Serialize)]
    struct RelayConfig {
        relay_ip: String,
        relay_port: u16,
        relay_token: Vec<u8>,
        auth_token: Vec<u8>,
        integrity_key: Vec<u8>,
        warp_mi_tag_len: u32,
    }
    to_js_object(&RelayConfig {
        relay_ip,
        relay_port,
        relay_token,
        auth_token,
        integrity_key,
        warp_mi_tag_len: relay_data.warp_mi_tag_len.unwrap_or(4),
    })
}

/// The participant SSRC the engine derives for `slot_word` (0 = audio, 1 = video).
#[wasm_bindgen(js_name = deriveCallParticipantSsrc)]
pub fn derive_call_participant_ssrc(call_id: &str, self_lid: &str, slot_word: u32) -> u32 {
    let participant_id = wacore_voip::voip_control::ssrc::format_e2e_srtp_participant_id(self_lid);
    wacore_voip::voip_control::ssrc::derive_wasm_participant_ssrc(call_id, &participant_id, slot_word)
}

pub(crate) struct RngTxIds;
impl TxIdSource for RngTxIds {
    fn next_tx_id(&mut self) -> [u8; 12] {
        rand::random()
    }
}

#[derive(serde::Deserialize)]
struct EngineConfigJson {
    call_id: String,
    /// "incoming" or "outgoing".
    direction: String,
    self_lid: String,
    peer_lid: String,
    call_key: Vec<u8>,
    ssrc: u32,
    relay_token: Vec<u8>,
    #[serde(default)]
    auth_token: Vec<u8>,
    relay_ip: String,
    relay_port: u16,
    integrity_key: Vec<u8>,
    warp_mi_tag_len: usize,
    enable_media: bool,
    #[serde(default)]
    enable_video: bool,
    enable_sframe: bool,
    /// "mlow" (PCM in/out, default) or "opus" (complete Opus packets in/out).
    #[serde(default)]
    audio: String,
}

fn call_config_from_json(json: &str) -> Result<CallConfig, String> {
    let c: EngineConfigJson =
        serde_json::from_str(json).map_err(|e| format!("invalid engine config JSON: {e}"))?;
    let direction = match c.direction.as_str() {
        "incoming" => CallDirection::Incoming,
        "outgoing" => CallDirection::Outgoing,
        other => return Err(format!("direction must be incoming|outgoing, got {other:?}")),
    };
    Ok(CallConfig {
        call_id: c.call_id,
        direction,
        self_lid: c.self_lid,
        peer_lid: c.peer_lid,
        call_key: c.call_key,
        ssrc: c.ssrc,
        audio: if c.audio == "opus" {
            AudioConfig::encoded(AudioFormat::OPUS_16KHZ_60MS)
        } else {
            AudioConfig::MLOW_PCM
        },
        relay_token: c.relay_token,
        auth_token: c.auth_token,
        relay_ip: c.relay_ip,
        relay_port: c.relay_port,
        integrity_key: c.integrity_key,
        warp_mi_tag_len: c.warp_mi_tag_len,
        enable_media: c.enable_media,
        enable_video: c.enable_video,
        enable_sframe: c.enable_sframe,
    })
}

/// What `pollOutput` yields.
const OUT_TIMEOUT: i32 = 0;
const OUT_TRANSMIT: i32 = 1;
const OUT_PLAYOUT: i32 = 2;
const OUT_EVENT: i32 = 3;
const OUT_VIDEO: i32 = 4;
const OUT_OTHER: i32 = 5;
const OUT_ENCODED: i32 = 6;
const OUT_RECONNECT: i32 = 7;

/// Sans-IO call engine: the relay control plane (STUN allocate, keepalive) and the media plane (MLow PCM, E2E-SRTP).
/// Feed inputs, then drain `pollOutput` until it returns 0 and arm one timer for `lastTimeout`.
#[wasm_bindgen]
pub struct CallEngine {
    inner: CoreCallEngine,
    last: Option<Output>,
}

impl CallEngine {
    pub(crate) fn from_core(inner: CoreCallEngine) -> CallEngine {
        CallEngine { inner, last: None }
    }
    pub(crate) fn core_mut(&mut self) -> &mut CoreCallEngine {
        &mut self.inner
    }
}

#[wasm_bindgen]
impl CallEngine {
    #[wasm_bindgen(js_name = create)]
    pub fn create(config_json: &str) -> Result<CallEngine, JsValue> {
        let cfg = call_config_from_json(config_json).map_err(|e| JsValue::from_str(&e))?;
        CoreCallEngine::new(cfg, Box::new(RngTxIds))
            .map(|inner| CallEngine { inner, last: None })
            .map_err(|e| JsValue::from_str(&format!("CallEngine.create: {e}")))
    }

    /// Start the call (relay allocate). `now` is monotonic ms, `wallclockMs` unix epoch ms.
    pub fn start(&mut self, now: f64, wallclock_ms: f64) {
        self.inner.start(now as u64, wallclock_ms as u64);
    }

    #[wasm_bindgen(js_name = handleRelayPacket)]
    pub fn handle_relay_packet(&mut self, now: f64, packet: &[u8]) {
        self.inner.handle_input(now as u64, Input::RelayPacket(packet));
    }

    /// One 60 ms mic frame: exactly 960 samples, 16 kHz mono.
    #[wasm_bindgen(js_name = handleMicFrame)]
    pub fn handle_mic_frame(&mut self, now: f64, pcm: &[i16]) {
        self.inner.handle_input(now as u64, Input::MicFrame(pcm));
    }

    /// One H.264 Annex-B access unit (video calls).
    /// One complete encoded audio payload (Opus mode).
    #[wasm_bindgen(js_name = handleEncodedAudio)]
    pub fn handle_encoded_audio(&mut self, now: f64, payload: &[u8]) {
        self.inner.handle_input(now as u64, Input::EncodedAudio(payload));
    }

    #[wasm_bindgen(js_name = handleVideoFrame)]
    pub fn handle_video_frame(&mut self, now: f64, frame: &[u8]) {
        self.inner.handle_input(now as u64, Input::VideoFrame(frame));
    }

    /// The replacement relay transport is open: start the Allocate response budget.
    #[wasm_bindgen(js_name = relayReconnected)]
    pub fn relay_reconnected(&mut self, now: f64) {
        self.inner.relay_reconnected(now as u64);
    }

    /// The engine's media counters as text (RTP received, SRTP failures, silence reason ...), for diagnostics.
    #[wasm_bindgen(js_name = mediaStats)]
    pub fn media_stats(&self) -> String {
        format!("{:?}", self.inner.media_stats())
    }

    #[wasm_bindgen(js_name = handleTimeout)]
    pub fn handle_timeout(&mut self, now: f64) {
        self.inner.handle_input(now as u64, Input::Timeout);
    }

    /// Drain one output: 0 = drained (timer armed), 1 = datagram to send, 2 = PCM to play, 3 = event, 4 = video
    /// access unit from the peer, 5 = something else (ignore).
    #[wasm_bindgen(js_name = pollOutput)]
    pub fn poll_output(&mut self) -> i32 {
        let out = self.inner.poll_output();
        let kind = match &out {
            Output::Timeout(_) => OUT_TIMEOUT,
            Output::Transmit(_) | Output::RetransmitVideo(_) => OUT_TRANSMIT,
            Output::Playout(_) => OUT_PLAYOUT,
            Output::Event(_) => OUT_EVENT,
            Output::VideoPlayout(_) => OUT_VIDEO,
            Output::EncodedAudio(_) => OUT_ENCODED,
            Output::ReconnectRelay(_) => OUT_RECONNECT,
            _ => OUT_OTHER,
        };
        self.last = Some(out);
        kind
    }

    /// The relay (`ip:port`) the last `OUT_RECONNECT` output asks us to dial.
    #[wasm_bindgen(js_name = takeReconnect)]
    pub fn take_reconnect(&mut self) -> Option<String> {
        match self.last.take() {
            Some(Output::ReconnectRelay(a)) => Some(a.to_string()),
            other => {
                self.last = other;
                None
            }
        }
    }

    #[wasm_bindgen(js_name = takeTransmit)]
    pub fn take_transmit(&mut self) -> Option<Vec<u8>> {
        match self.last.take() {
            Some(Output::Transmit(b)) | Some(Output::RetransmitVideo(b)) => Some(b.to_vec()),
            other => {
                self.last = other;
                None
            }
        }
    }

    #[wasm_bindgen(js_name = takePlayout)]
    pub fn take_playout(&mut self) -> Option<Vec<i16>> {
        match self.last.take() {
            Some(Output::Playout(p)) => Some(p),
            other => {
                self.last = other;
                None
            }
        }
    }

    /// Who sent the encoded audio of the last `6` output (group calls: the participant's device JID), or empty.
    #[wasm_bindgen(js_name = encodedSender)]
    pub fn encoded_sender(&self) -> String {
        match &self.last {
            Some(Output::EncodedAudio(f)) => f
                .device
                .as_ref()
                .or(f.sender.as_ref())
                .map(|j| j.to_string())
                .unwrap_or_default(),
            _ => String::new(),
        }
    }

    /// Install the shared group epoch (the raw key the creator delivered in `enc_rekey`).
    #[wasm_bindgen(js_name = applyGroupEpoch)]
    pub fn apply_group_epoch(&mut self, transaction_id: u32, raw_epoch: &[u8]) -> Result<String, JsValue> {
        self.inner
            .apply_group_raw_epoch(transaction_id, raw_epoch)
            .map(|r| format!("{r:?}"))
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Bring the video plane up in a running call. `gated` holds our outbound video back until the peer accepted.
    #[wasm_bindgen(js_name = enableVideo)]
    pub fn enable_video(&mut self, gated: bool) -> bool {
        if gated {
            self.inner.enable_video_gated()
        } else {
            self.inner.enable_video()
        }
    }

    /// Stop sending and decoding video (the camera went off); audio carries on.
    #[wasm_bindgen(js_name = disableVideo)]
    pub fn disable_video(&mut self) {
        self.inner.disable_video();
    }

    #[wasm_bindgen(js_name = isVideoEnabled)]
    pub fn is_video_enabled(&self) -> bool {
        self.inner.is_video_enabled()
    }

    /// React in a group call (an emoji; the empty string takes the reaction back).
    #[wasm_bindgen(js_name = sendGroupReaction)]
    pub fn send_group_reaction(&mut self, now: f64, emoji: &str) -> Result<(), JsValue> {
        self.inner
            .send_group_reaction(now as u64, emoji)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// The peer's encoded audio payload of the last `6` output (Opus mode).
    #[wasm_bindgen(js_name = takeEncodedAudio)]
    pub fn take_encoded_audio(&mut self) -> Option<Vec<u8>> {
        match self.last.take() {
            Some(Output::EncodedAudio(f)) => Some(f.data.to_vec()),
            other => {
                self.last = other;
                None
            }
        }
    }

    /// The peer's video access unit (Annex-B bytes) of the last `4` output.
    #[wasm_bindgen(js_name = takeVideo)]
    pub fn take_video(&mut self) -> Option<Vec<u8>> {
        match self.last.take() {
            Some(Output::VideoPlayout(v)) => Some(v.data.to_vec()),
            other => {
                self.last = other;
                None
            }
        }
    }

    /// Name of the last `3` output's event (`RelayAllocated`, `MediaConnected`, ...); empty if none.
    #[wasm_bindgen(js_name = eventName)]
    pub fn event_name(&self) -> String {
        match &self.last {
            Some(Output::Event(e)) => {
                let d = format!("{e:?}");
                d.split(['(', ' ', '{']).next().unwrap_or("").to_string()
            }
            _ => String::new(),
        }
    }

    /// The whole last event as text (e.g. who reacted with which emoji).
    #[wasm_bindgen(js_name = eventDetail)]
    pub fn event_detail(&self) -> String {
        match &self.last {
            Some(Output::Event(e)) => format!("{e:?}"),
            _ => String::new(),
        }
    }

    /// STUN error code of a `RelayAllocateFailed` event, or -1.
    #[wasm_bindgen(js_name = eventCode)]
    pub fn event_code(&self) -> i32 {
        match &self.last {
            Some(Output::Event(CallEvent::RelayAllocateFailed(c))) => *c as i32,
            _ => -1,
        }
    }

    /// Deadline (ms) of the last `0` output, or -1 for none.
    #[wasm_bindgen(js_name = lastTimeout)]
    pub fn last_timeout(&self) -> f64 {
        match &self.last {
            Some(Output::Timeout(m)) if *m != NEVER => *m as f64,
            _ => -1.0,
        }
    }

    #[wasm_bindgen(js_name = pollTimeout)]
    pub fn poll_timeout(&self) -> f64 {
        match self.inner.poll_timeout() {
            Some(m) if m != NEVER => m as f64,
            _ => -1.0,
        }
    }

    /// Re-derive the receive keys once the answering device is known.
    #[wasm_bindgen(js_name = rekeyRecv)]
    pub fn rekey_recv(&mut self, answering_peer_lid: &str) -> bool {
        self.inner.rekey_recv(answering_peer_lid)
    }

    #[wasm_bindgen(js_name = isAllocated)]
    pub fn is_allocated(&self) -> bool {
        self.inner.is_allocated()
    }

    #[wasm_bindgen(js_name = isTerminated)]
    pub fn is_terminated(&self) -> bool {
        self.inner.is_terminated()
    }
}


/// Decode a node as `encodeNode` produced it (data-type byte, optional zlib, marshalled node).
pub(crate) fn unpack_node(encoded: &[u8]) -> Result<(Vec<u8>, ()), JsValue> {
    let unpacked = wacore_binary::util::unpack(encoded)
        .map_err(|e| JsValue::from_str(&format!("unpack error: {e}")))?;
    Ok((unpacked.into_owned(), ()))
}

/// A built `Node` as the plain `{tag, attrs, content}` object `sendNode` takes (bytes as `Uint8Array`).
pub(crate) fn node_to_js_value(node: &wacore_binary::Node) -> JsValue {
    let obj = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&obj, &JsValue::from_str("tag"), &JsValue::from_str(&node.tag));
    let attrs = js_sys::Object::new();
    for (k, v) in node.attrs.iter() {
        let s = match v {
            wacore_binary::NodeValue::String(s) => s.to_string(),
            wacore_binary::NodeValue::Jid(j) => j.to_string(),
        };
        let _ = js_sys::Reflect::set(&attrs, &JsValue::from_str(k), &JsValue::from_str(&s));
    }
    let _ = js_sys::Reflect::set(&obj, &JsValue::from_str("attrs"), &attrs);
    if let Some(content) = &node.content {
        let value: JsValue = match content {
            wacore_binary::NodeContent::Bytes(b) => js_sys::Uint8Array::from(b.as_slice()).into(),
            wacore_binary::NodeContent::String(s) => JsValue::from_str(s),
            wacore_binary::NodeContent::Nodes(ns) => {
                let arr = js_sys::Array::new();
                for n in ns.iter() {
                    arr.push(&node_to_js_value(n));
                }
                arr.into()
            }
        };
        let _ = js_sys::Reflect::set(&obj, &JsValue::from_str("content"), &value);
    }
    obj.into()
}
