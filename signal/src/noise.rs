use napi::bindgen_prelude::*;
use napi_derive::napi;
use wacore_binary::consts::WA_CONN_HEADER;
use wacore_libsignal::protocol::KeyPair;
use wacore_noise::framing::{encode_frame as encode_noise_frame, FrameDecoder as CoreFrameDecoder};
use wacore_noise::{NoiseCertPolicy, NoiseCipher, XxHandshakeState};

fn js_err(error: impl std::fmt::Display) -> napi::Error {
  napi::Error::from_reason(error.to_string())
}

#[napi]
pub fn wa_conn_header() -> Buffer {
  Buffer::from(WA_CONN_HEADER.to_vec())
}

#[napi]
pub fn encode_frame(payload: Buffer, header: Option<Buffer>) -> napi::Result<Buffer> {
  encode_noise_frame(&payload, header.as_deref())
    .map(Buffer::from)
    .map_err(js_err)
}

#[napi]
pub struct FrameDecoder {
  inner: CoreFrameDecoder,
}

#[napi]
impl FrameDecoder {
  #[napi(constructor)]
  pub fn new() -> Self {
    Self {
      inner: CoreFrameDecoder::new(),
    }
  }

  #[napi]
  pub fn feed(&mut self, data: Buffer) {
    self.inner.feed(&data);
  }

  #[napi]
  pub fn next_frame(&mut self) -> Option<Buffer> {
    self
      .inner
      .decode_frame()
      .map(|frame| Buffer::from(frame.to_vec()))
  }
}

impl Default for FrameDecoder {
  fn default() -> Self {
    Self::new()
  }
}

#[napi]
pub struct NoiseXxHandshake {
  inner: Option<XxHandshakeState>,
}

#[napi]
impl NoiseXxHandshake {
  #[napi(constructor)]
  pub fn new(
    static_private: Buffer,
    static_public: Buffer,
    client_payload: Buffer,
    prologue: Option<Buffer>,
  ) -> napi::Result<Self> {
    if static_public.len() != 32 {
      return Err(js_err("staticPublic must be 32 bytes"));
    }

    let mut prefixed_public = Vec::with_capacity(33);
    prefixed_public.push(0x05);
    prefixed_public.extend_from_slice(&static_public);
    let key_pair =
      KeyPair::from_public_and_private(&prefixed_public, &static_private).map_err(js_err)?;
    let prologue = prologue.unwrap_or_else(|| Buffer::from(WA_CONN_HEADER.to_vec()));
    let state = XxHandshakeState::new_with_cert_policy(
      key_pair,
      client_payload.to_vec(),
      &prologue,
      NoiseCertPolicy::Strict,
    )
    .map_err(js_err)?;

    Ok(Self { inner: Some(state) })
  }

  #[napi]
  pub fn build_client_hello(&self) -> napi::Result<Buffer> {
    self
      .state()?
      .build_client_hello()
      .map(Buffer::from)
      .map_err(js_err)
  }

  #[napi]
  pub fn read_server_hello_and_build_client_finish(
    &mut self,
    server_hello: Buffer,
  ) -> napi::Result<Buffer> {
    self
      .inner
      .as_mut()
      .ok_or_else(|| js_err("handshake already finished"))?
      .read_server_hello_and_build_client_finish(&server_hello)
      .map(Buffer::from)
      .map_err(js_err)
  }

  #[napi]
  pub fn finish(&mut self) -> napi::Result<NoiseTransport> {
    let state = self
      .inner
      .take()
      .ok_or_else(|| js_err("handshake already finished"))?;
    let outcome = state.finish().map_err(js_err)?;
    Ok(NoiseTransport {
      write: outcome.write_cipher,
      read: outcome.read_cipher,
      write_counter: 0,
      read_counter: 0,
    })
  }
}

impl NoiseXxHandshake {
  fn state(&self) -> napi::Result<&XxHandshakeState> {
    self
      .inner
      .as_ref()
      .ok_or_else(|| js_err("handshake already finished"))
  }
}

#[napi]
pub struct NoiseTransport {
  write: NoiseCipher,
  read: NoiseCipher,
  write_counter: u32,
  read_counter: u32,
}

#[napi]
impl NoiseTransport {
  #[napi]
  pub fn encrypt(&mut self, plaintext: Buffer) -> napi::Result<Buffer> {
    let mut output = plaintext.to_vec();
    self
      .write
      .encrypt_in_place_with_counter(self.write_counter, &mut output)
      .map_err(js_err)?;
    self.write_counter = self
      .write_counter
      .checked_add(1)
      .ok_or_else(|| js_err("write counter exhausted"))?;
    Ok(Buffer::from(output))
  }

  #[napi]
  pub fn decrypt(&mut self, ciphertext: Buffer) -> napi::Result<Buffer> {
    let mut output = ciphertext.to_vec();
    self
      .read
      .decrypt_in_place_with_counter(self.read_counter, &mut output)
      .map_err(js_err)?;
    self.read_counter = self
      .read_counter
      .checked_add(1)
      .ok_or_else(|| js_err("read counter exhausted"))?;
    Ok(Buffer::from(output))
  }
}
