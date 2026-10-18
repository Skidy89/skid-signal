use prost::Message;
use signal_proto::signal::wire::{PreKeyWhisperMessage, WhisperMessage};

use crate::crypto::{hmac_sha256, verify_mac, CryptoError};

pub const CURRENT_VERSION: u8 = 3;
pub const VERSION_BYTE: u8 = (CURRENT_VERSION << 4) | CURRENT_VERSION; // 0x33
pub const MAC_LEN: usize = 8;

#[derive(Debug, thiserror::Error)]
pub enum WireError {
  #[error("Incompatible version number on WhisperMessage")]
  IncompatibleVersion,
  #[error("Message too short")]
  TooShort,
  #[error("protobuf: {0}")]
  Decode(#[from] prost::DecodeError),
}

pub fn version_ok(b: u8) -> bool {
  (b & 0x0f) <= CURRENT_VERSION && (b >> 4) >= CURRENT_VERSION
}

fn mac_input(sender_identity: &[u8], receiver_identity: &[u8], proto: &[u8]) -> Vec<u8> {
  let mut v = Vec::with_capacity(sender_identity.len() + receiver_identity.len() + 1 + proto.len());
  v.extend_from_slice(sender_identity);
  v.extend_from_slice(receiver_identity);
  v.push(VERSION_BYTE);
  v.extend_from_slice(proto);
  v
}

pub fn encode_whisper(
  msg: &WhisperMessage,
  mac_key: &[u8],
  our_identity: &[u8],
  their_identity: &[u8],
) -> Vec<u8> {
  let proto = msg.encode_to_vec();
  let mac = hmac_sha256(mac_key, &mac_input(our_identity, their_identity, &proto));
  let mut out = Vec::with_capacity(1 + proto.len() + MAC_LEN);
  out.push(VERSION_BYTE);
  out.extend_from_slice(&proto);
  out.extend_from_slice(&mac[..MAC_LEN]);
  out
}

pub struct DecodedWhisper<'a> {
  pub message: WhisperMessage,
  proto: &'a [u8],
  mac: &'a [u8],
}

pub fn decode_whisper(buf: &[u8]) -> Result<DecodedWhisper<'_>, WireError> {
  if buf.len() < 1 + MAC_LEN {
    return Err(WireError::TooShort);
  }
  if !version_ok(buf[0]) {
    return Err(WireError::IncompatibleVersion);
  }
  let proto = &buf[1..buf.len() - MAC_LEN];
  let mac = &buf[buf.len() - MAC_LEN..];
  let message = WhisperMessage::decode(proto)?;
  Ok(DecodedWhisper {
    message,
    proto,
    mac,
  })
}

impl DecodedWhisper<'_> {
  pub fn verify_mac(
    &self,
    mac_key: &[u8],
    remote_identity: &[u8],
    our_identity: &[u8],
  ) -> Result<(), CryptoError> {
    verify_mac(
      mac_key,
      &mac_input(remote_identity, our_identity, self.proto),
      self.mac,
    )
  }
}

pub fn encode_prekey_whisper(msg: &PreKeyWhisperMessage) -> Vec<u8> {
  let proto = msg.encode_to_vec();
  let mut out = Vec::with_capacity(1 + proto.len());
  out.push(VERSION_BYTE);
  out.extend_from_slice(&proto);
  out
}

pub fn decode_prekey_whisper(buf: &[u8]) -> Result<PreKeyWhisperMessage, WireError> {
  if buf.is_empty() {
    return Err(WireError::TooShort);
  }
  if !version_ok(buf[0]) {
    return Err(WireError::IncompatibleVersion);
  }
  Ok(PreKeyWhisperMessage::decode(&buf[1..])?)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn sample() -> WhisperMessage {
    WhisperMessage {
      ephemeral_key: Some(vec![5u8; 33]),
      counter: Some(0),
      previous_counter: Some(0),
      ciphertext: Some(vec![1, 2, 3]),
    }
  }

  #[test]
  fn whisper_roundtrip_and_mac() {
    let (alice, bob) = ([9u8; 33], [7u8; 33]);
    let wire = encode_whisper(&sample(), &[3u8; 32], &alice, &bob);
    assert_eq!(wire[0], 0x33);

    let d = decode_whisper(&wire).unwrap();
    assert_eq!(d.message, sample());
    assert!(d.verify_mac(&[3u8; 32], &alice, &bob).is_ok());
    assert!(d.verify_mac(&[3u8; 32], &bob, &alice).is_err());
    assert!(d.verify_mac(&[4u8; 32], &alice, &bob).is_err());
  }

  #[test]
  fn zero_counters_are_written_explicitly() {
    let wire = encode_whisper(&sample(), &[3u8; 32], &[9u8; 33], &[7u8; 33]);
    assert_eq!(&wire[1..3], &[0x0a, 0x21]);
    assert_eq!(&wire[36..40], &[0x10, 0x00, 0x18, 0x00]);
  }

  #[test]
  fn rejects_bad_version_and_short_input() {
    assert!(matches!(
      decode_whisper(&[0x33; 5]),
      Err(WireError::TooShort)
    ));
    let mut wire = encode_whisper(&sample(), &[3u8; 32], &[9u8; 33], &[7u8; 33]);
    wire[0] = 0x22; // nibble < 3
    assert!(matches!(
      decode_whisper(&wire),
      Err(WireError::IncompatibleVersion)
    ));
    wire[0] = 0x34; // nibble > 3
    assert!(matches!(
      decode_whisper(&wire),
      Err(WireError::IncompatibleVersion)
    ));
  }

  #[test]
  fn prekey_roundtrip() {
    let m = PreKeyWhisperMessage {
      registration_id: Some(1234),
      pre_key_id: Some(7),
      signed_pre_key_id: Some(2),
      base_key: Some(vec![5u8; 33]),
      identity_key: Some(vec![5u8; 33]),
      message: Some(vec![0x33, 1, 2, 3]),
    };
    let wire = encode_prekey_whisper(&m);
    assert_eq!(wire[0], 0x33);
    assert_eq!(decode_prekey_whisper(&wire).unwrap(), m);
  }
}
