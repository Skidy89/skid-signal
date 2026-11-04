// velowa (https://github.com/7ucg/velowa) (c) 2026 Baron. Copying any part of this file, however small, requires credit: see LICENSE.
//! Noise XX handshake + transport cipher + WA frame codec.
//!
//! Stateful wasm classes, because the handshake and the transport counters are
//! genuinely stateful and threading them through free functions would push the
//! invariants (counter monotonicity, single use of the handshake) onto TS:
//!
//! ```ts
//! const hs = new NoiseXxHandshake(staticPriv, staticPub, clientPayload)
//! send(encodeFrame(hs.buildClientHello(), WA_CONN_HEADER))
//! send(encodeFrame(hs.readServerHelloAndBuildClientFinish(serverHello)))
//! const transport = hs.finish()          // consumes `hs`
//! transport.encrypt(...) / transport.decrypt(...)
//! ```
//!
//! Server-cert-chain verification is always `Strict`; the test-only bypass of
//! `wacore-noise` is deliberately not exported.

use wacore_libsignal::protocol::KeyPair;
use wacore_noise::framing::{FrameDecoder as InnerDecoder, encode_frame as inner_encode_frame};
use wacore_noise::{NoiseCertPolicy, NoiseCipher, XxHandshakeState};
use wasm_bindgen::prelude::*;

fn err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

/// The 4-byte connection header (`WA`, magic, dict version) sent once in front of the first frame.
#[wasm_bindgen(js_name = waConnHeader)]
pub fn wa_conn_header() -> Vec<u8> {
    wacore_binary::consts::WA_CONN_HEADER.to_vec()
}

/// Wrap a payload in a 3-byte length-prefixed frame; `header` is prepended once (first frame only).
#[wasm_bindgen(js_name = encodeFrame)]
pub fn encode_frame(payload: &[u8], header: Option<Vec<u8>>) -> Result<Vec<u8>, JsError> {
    inner_encode_frame(payload, header.as_deref()).map_err(err)
}

/// Incremental frame reassembly: `feed` raw socket bytes, then drain with `nextFrame`.
#[wasm_bindgen]
pub struct FrameDecoder {
    inner: InnerDecoder,
}

#[wasm_bindgen]
impl FrameDecoder {
    #[wasm_bindgen(constructor)]
    pub fn new() -> FrameDecoder {
        FrameDecoder {
            inner: InnerDecoder::new(),
        }
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.inner.feed(data);
    }

    /// The next complete frame payload, or `undefined` when more bytes are needed.
    #[wasm_bindgen(js_name = nextFrame)]
    pub fn next_frame(&mut self) -> Option<Vec<u8>> {
        self.inner.decode_frame().map(|b| b.to_vec())
    }
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Client side of the Noise XX handshake (first connect / pairing).
#[wasm_bindgen]
pub struct NoiseXxHandshake {
    inner: Option<XxHandshakeState>,
}

#[wasm_bindgen]
impl NoiseXxHandshake {
    /// `staticPrivate`/`staticPublic`: the device's 32-byte Noise static key pair.
    /// `clientPayload`: encoded ClientPayload protobuf. `prologue` defaults to the WA connection header.
    #[wasm_bindgen(constructor)]
    pub fn new(
        static_private: &[u8],
        static_public: &[u8],
        client_payload: Vec<u8>,
        prologue: Option<Vec<u8>>,
    ) -> Result<NoiseXxHandshake, JsError> {
        // Callers hold raw 32-byte X25519 keys; libsignal's public key wants the 0x05 type prefix.
        if static_public.len() != 32 {
            return Err(err("staticPublic must be 32 bytes"));
        }
        let mut prefixed = Vec::with_capacity(33);
        prefixed.push(0x05);
        prefixed.extend_from_slice(static_public);
        let kp = KeyPair::from_public_and_private(&prefixed, static_private).map_err(err)?;
        let prologue = prologue.unwrap_or_else(|| wacore_binary::consts::WA_CONN_HEADER.to_vec());
        let inner = XxHandshakeState::new_with_cert_policy(
            kp,
            client_payload,
            &prologue,
            NoiseCertPolicy::Strict,
        )
        .map_err(err)?;
        Ok(NoiseXxHandshake { inner: Some(inner) })
    }

    /// Encoded HandshakeMessage carrying the client ephemeral (not yet framed).
    #[wasm_bindgen(js_name = buildClientHello)]
    pub fn build_client_hello(&self) -> Result<Vec<u8>, JsError> {
        self.state()?.build_client_hello().map_err(err)
    }

    /// Verifies the server hello (incl. certificate chain) and returns the encoded client finish.
    #[wasm_bindgen(js_name = readServerHelloAndBuildClientFinish)]
    pub fn read_server_hello_and_build_client_finish(
        &mut self,
        server_hello: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        self.inner
            .as_mut()
            .ok_or_else(|| err("handshake already finished"))?
            .read_server_hello_and_build_client_finish(server_hello)
            .map_err(err)
    }

    /// Completes the handshake and yields the transport ciphers. Consumes the handshake.
    pub fn finish(&mut self) -> Result<NoiseTransport, JsError> {
        let state = self
            .inner
            .take()
            .ok_or_else(|| err("handshake already finished"))?;
        let out = state.finish().map_err(err)?;
        Ok(NoiseTransport {
            write: out.write_cipher,
            read: out.read_cipher,
            write_counter: 0,
            read_counter: 0,
        })
    }

    fn state(&self) -> Result<&XxHandshakeState, JsError> {
        self.inner
            .as_ref()
            .ok_or_else(|| err("handshake already finished"))
    }
}

/// Post-handshake AES-256-GCM transport. Counters live here so TS cannot desync them.
#[wasm_bindgen]
pub struct NoiseTransport {
    write: NoiseCipher,
    read: NoiseCipher,
    write_counter: u32,
    read_counter: u32,
}

#[wasm_bindgen]
impl NoiseTransport {
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
        let out = self
            .write
            .encrypt_with_counter(self.write_counter, plaintext)
            .map_err(err)?;
        self.write_counter = self
            .write_counter
            .checked_add(1)
            .ok_or_else(|| err("write counter exhausted"))?;
        Ok(out)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
        let mut buf = ciphertext.to_vec();
        self.read
            .decrypt_in_place_with_counter(self.read_counter, &mut buf)
            .map_err(err)?;
        self.read_counter = self
            .read_counter
            .checked_add(1)
            .ok_or_else(|| err("read counter exhausted"))?;
        Ok(buf)
    }
}
