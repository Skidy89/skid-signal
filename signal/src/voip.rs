use napi::bindgen_prelude::*;
use napi_derive::napi;
use wacore_voip::voip::{
  AudioConfig, AudioFormat, CallConfig, CallDirection, CallEngine as CoreCallEngine, CallEvent,
  Input, Output, TxIdSource, NEVER,
};

fn js_err(error: impl std::fmt::Display) -> napi::Error {
  napi::Error::from_reason(error.to_string())
}

struct RandomTxIds;

impl TxIdSource for RandomTxIds {
  fn next_tx_id(&mut self) -> [u8; 12] {
    rand::random()
  }
}

#[napi(object)]
pub struct VoipConfig {
  pub call_id: String,
  pub direction: String,
  pub self_lid: String,
  pub peer_lid: String,
  pub call_key: Buffer,
  pub ssrc: u32,
  pub relay_token: Buffer,
  pub auth_token: Option<Buffer>,
  pub relay_ip: String,
  pub relay_port: u16,
  pub integrity_key: Buffer,
  pub warp_mi_tag_len: u32,
  pub enable_media: bool,
  pub enable_video: bool,
  pub enable_sframe: bool,
  pub audio: Option<String>,
}

#[napi(object)]
pub struct VoipOutput {
  pub kind: i32,
  pub data: Option<Buffer>,
  pub pcm: Option<Vec<i16>>,
  pub address: Option<String>,
  pub event: Option<String>,
  pub timeout: Option<f64>,
}

const OUT_TIMEOUT: i32 = 0;
const OUT_TRANSMIT: i32 = 1;
const OUT_PLAYOUT: i32 = 2;
const OUT_EVENT: i32 = 3;
const OUT_VIDEO: i32 = 4;
const OUT_OTHER: i32 = 5;
const OUT_ENCODED: i32 = 6;
const OUT_RECONNECT: i32 = 7;

#[napi]
pub struct CallEngine {
  inner: CoreCallEngine,
  last_timeout: Option<f64>,
  last_event_code: i32,
}

#[napi]
impl CallEngine {
  #[napi(factory)]
  pub fn create(config: VoipConfig) -> napi::Result<Self> {
    let direction = match config.direction.as_str() {
      "incoming" => CallDirection::Incoming,
      "outgoing" => CallDirection::Outgoing,
      value => {
        return Err(js_err(format!(
          "direction must be incoming|outgoing, got {value:?}"
        )))
      }
    };
    let audio = match config.audio.as_deref() {
      Some("opus") => AudioConfig::encoded(AudioFormat::OPUS_16KHZ_60MS),
      Some("mlow") | None => AudioConfig::MLOW_PCM,
      Some(value) => return Err(js_err(format!("audio must be mlow|opus, got {value:?}"))),
    };
    let core_config = CallConfig {
      call_id: config.call_id,
      direction,
      self_lid: config.self_lid,
      peer_lid: config.peer_lid,
      call_key: config.call_key.to_vec(),
      ssrc: config.ssrc,
      audio,
      relay_token: config.relay_token.to_vec(),
      auth_token: config
        .auth_token
        .map(|token| token.to_vec())
        .unwrap_or_default(),
      relay_ip: config.relay_ip,
      relay_port: config.relay_port,
      integrity_key: config.integrity_key.to_vec(),
      warp_mi_tag_len: usize::try_from(config.warp_mi_tag_len)
        .map_err(|_| js_err("warpMiTagLen is out of range"))?,
      enable_media: config.enable_media,
      enable_video: config.enable_video,
      enable_sframe: config.enable_sframe,
    };
    CoreCallEngine::new(core_config, Box::new(RandomTxIds))
      .map(|inner| Self {
        inner,
        last_timeout: None,
        last_event_code: -1,
      })
      .map_err(js_err)
  }

  #[napi]
  pub fn start(&mut self, now: f64, wallclock_ms: f64) -> napi::Result<()> {
    self.inner.start(
      as_millis(now, "now")?,
      as_millis(wallclock_ms, "wallclockMs")?,
    );
    Ok(())
  }

  #[napi]
  pub fn handle_relay_packet(&mut self, now: f64, packet: Buffer) -> napi::Result<()> {
    self
      .inner
      .handle_input(as_millis(now, "now")?, Input::RelayPacket(&packet));
    Ok(())
  }

  #[napi]
  pub fn handle_mic_frame(&mut self, now: f64, pcm: Vec<i16>) -> napi::Result<()> {
    self
      .inner
      .handle_input(as_millis(now, "now")?, Input::MicFrame(&pcm));
    Ok(())
  }

  #[napi]
  pub fn handle_encoded_audio(&mut self, now: f64, payload: Buffer) -> napi::Result<()> {
    self
      .inner
      .handle_input(as_millis(now, "now")?, Input::EncodedAudio(&payload));
    Ok(())
  }

  #[napi]
  pub fn handle_video_frame(&mut self, now: f64, frame: Buffer) -> napi::Result<()> {
    self
      .inner
      .handle_input(as_millis(now, "now")?, Input::VideoFrame(&frame));
    Ok(())
  }

  #[napi]
  pub fn handle_timeout(&mut self, now: f64) -> napi::Result<()> {
    self
      .inner
      .handle_input(as_millis(now, "now")?, Input::Timeout);
    Ok(())
  }

  #[napi]
  pub fn relay_reconnected(&mut self, now: f64) -> napi::Result<()> {
    self.inner.relay_reconnected(as_millis(now, "now")?);
    Ok(())
  }

  #[napi]
  pub fn poll_output(&mut self) -> VoipOutput {
    let output = self.inner.poll_output();
    let result = match output {
      Output::Timeout(deadline) => {
        self.last_timeout = (deadline != NEVER).then_some(deadline as f64);
        self.last_event_code = -1;
        VoipOutput {
          kind: OUT_TIMEOUT,
          data: None,
          pcm: None,
          address: None,
          event: None,
          timeout: self.last_timeout,
        }
      }
      Output::Transmit(data) | Output::RetransmitVideo(data) => {
        self.last_timeout = None;
        self.last_event_code = -1;
        VoipOutput {
          kind: OUT_TRANSMIT,
          data: Some(Buffer::from(data.to_vec())),
          pcm: None,
          address: None,
          event: None,
          timeout: None,
        }
      }
      Output::Playout(pcm) => {
        self.last_timeout = None;
        self.last_event_code = -1;
        VoipOutput {
          kind: OUT_PLAYOUT,
          data: None,
          pcm: Some(pcm),
          address: None,
          event: None,
          timeout: None,
        }
      }
      Output::EncodedAudio(frame) => {
        self.last_timeout = None;
        self.last_event_code = -1;
        VoipOutput {
          kind: OUT_ENCODED,
          data: Some(Buffer::from(frame.data.to_vec())),
          pcm: None,
          address: None,
          event: None,
          timeout: None,
        }
      }
      Output::VideoPlayout(frame) => {
        self.last_timeout = None;
        self.last_event_code = -1;
        VoipOutput {
          kind: OUT_VIDEO,
          data: Some(Buffer::from(frame.data.to_vec())),
          pcm: None,
          address: None,
          event: None,
          timeout: None,
        }
      }
      Output::Event(event) => {
        self.last_timeout = None;
        self.last_event_code = match &event {
          CallEvent::RelayAllocateFailed(code) => *code as i32,
          _ => -1,
        };
        VoipOutput {
          kind: OUT_EVENT,
          data: None,
          pcm: None,
          address: None,
          event: Some(format!("{event:?}")),
          timeout: None,
        }
      }
      Output::ReconnectRelay(address) => {
        self.last_timeout = None;
        self.last_event_code = -1;
        VoipOutput {
          kind: OUT_RECONNECT,
          data: None,
          pcm: None,
          address: Some(address.to_string()),
          event: None,
          timeout: None,
        }
      }
      _ => {
        self.last_timeout = None;
        self.last_event_code = -1;
        VoipOutput {
          kind: OUT_OTHER,
          data: None,
          pcm: None,
          address: None,
          event: None,
          timeout: None,
        }
      }
    };
    result
  }

  #[napi]
  pub fn media_stats(&self) -> String {
    format!("{:?}", self.inner.media_stats())
  }

  #[napi]
  pub fn poll_timeout(&self) -> Option<f64> {
    self
      .inner
      .poll_timeout()
      .filter(|value| *value != NEVER)
      .map(|value| value as f64)
  }

  #[napi]
  pub fn enable_video(&mut self, gated: bool) -> bool {
    if gated {
      self.inner.enable_video_gated()
    } else {
      self.inner.enable_video()
    }
  }

  #[napi]
  pub fn disable_video(&mut self) {
    self.inner.disable_video();
  }

  #[napi]
  pub fn is_video_enabled(&self) -> bool {
    self.inner.is_video_enabled()
  }

  #[napi]
  pub fn rekey_recv(&mut self, answering_peer_lid: String) -> bool {
    self.inner.rekey_recv(&answering_peer_lid)
  }

  #[napi]
  pub fn is_allocated(&self) -> bool {
    self.inner.is_allocated()
  }

  #[napi]
  pub fn is_terminated(&self) -> bool {
    self.inner.is_terminated()
  }

  #[napi]
  pub fn last_timeout(&self) -> Option<f64> {
    self.last_timeout
  }

  #[napi]
  pub fn event_code(&self) -> i32 {
    self.last_event_code
  }
}

fn as_millis(value: f64, name: &str) -> napi::Result<u64> {
  if !value.is_finite() || value < 0.0 || value > u64::MAX as f64 {
    return Err(js_err(format!(
      "{name} must be a finite non-negative millisecond value"
    )));
  }
  Ok(value as u64)
}
