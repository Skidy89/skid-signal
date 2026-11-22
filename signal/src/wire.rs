use hmac::{Hmac, Mac};
use prost::Message;
use sha2::Sha256;
use signal_proto::signal::wire::{PreKeyWhisperMessage, WhisperMessage};
use subtle::ConstantTimeEq;

use crate::crypto::CryptoError;

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

fn whisper_mac(
  key: &[u8],
  sender_identity: &[u8],
  receiver_identity: &[u8],
  proto: &[u8],
) -> [u8; 32] {
  let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
  mac.update(sender_identity);
  mac.update(receiver_identity);
  mac.update(&[VERSION_BYTE]);
  mac.update(proto);
  mac.finalize().into_bytes().into()
}

pub fn encode_whisper(
  msg: &WhisperMessage,
  mac_key: &[u8],
  our_identity: &[u8],
  their_identity: &[u8],
) -> Vec<u8> {
  let mut out = Vec::with_capacity(1 + msg.encoded_len() + MAC_LEN);
  out.push(VERSION_BYTE);
  msg.encode(&mut out).expect("Vec has capacity for protobuf");
  let mac = whisper_mac(mac_key, our_identity, their_identity, &out[1..]);
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
    let mac = whisper_mac(mac_key, remote_identity, our_identity, self.proto);
    if bool::from(mac[..MAC_LEN].ct_eq(self.mac)) {
      Ok(())
    } else {
      Err(CryptoError::BadMac)
    }
  }
}

pub fn encode_prekey_whisper(msg: &PreKeyWhisperMessage) -> Vec<u8> {
  let mut out = Vec::with_capacity(1 + msg.encoded_len());
  out.push(VERSION_BYTE);
  msg.encode(&mut out).expect("Vec has capacity for protobuf");
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
  fn whisper_encoding_allocates_only_output() {
    let mut msg = sample();
    msg.ciphertext = Some(vec![0xa5; 65536]);
    let (wire, allocations) =
      crate::test_alloc::measure(|| encode_whisper(&msg, &[3; 32], &[9; 33], &[7; 33]));
    assert_eq!(decode_whisper(&wire).unwrap().message, msg);
    assert_eq!(allocations, 1);
  }

  #[test]
  fn whisper_mac_verification_does_not_allocate() {
    let wire = encode_whisper(&sample(), &[3; 32], &[9; 33], &[7; 33]);
    let decoded = decode_whisper(&wire).unwrap();
    let (result, allocations) =
      crate::test_alloc::measure(|| decoded.verify_mac(&[3; 32], &[9; 33], &[7; 33]));
    result.unwrap();
    assert_eq!(allocations, 0);
  }

  #[test]
  fn prekey_encoding_allocates_only_output() {
    let msg = PreKeyWhisperMessage {
      message: Some(vec![0xa5; 65536]),
      ..Default::default()
    };
    let (wire, allocations) = crate::test_alloc::measure(|| encode_prekey_whisper(&msg));
    assert_eq!(decode_prekey_whisper(&wire).unwrap(), msg);
    assert_eq!(allocations, 1);
  }

  #[test]
  fn whisper_matches_independent_mac_vector_and_legacy_version_policy() {
    // HMAC-SHA256 vector computed independently with Python's hmac over the legacy concatenation.
    let expected_hex = "330a21050505050505050505050505050505050505050505050505050505050505050505100018002203010203a16f53c5beb1f800";
    let expected: Vec<u8> = (0..expected_hex.len())
      .step_by(2)
      .map(|i| u8::from_str_radix(&expected_hex[i..i + 2], 16).unwrap())
      .collect();
    let wire = encode_whisper(&sample(), &[3; 32], &[9; 33], &[7; 33]);
    assert_eq!(wire, expected);
    for version in [0x33, 0x32, 0x43] {
      let mut input = expected.clone();
      input[0] = version;
      decode_whisper(&input)
        .unwrap()
        .verify_mac(&[3; 32], &[9; 33], &[7; 33])
        .unwrap();
    }
    for index in 1..expected.len() {
      let mut input = expected.clone();
      input[index] ^= 1;
      if let Ok(decoded) = decode_whisper(&input) {
        assert!(decoded.verify_mac(&[3; 32], &[9; 33], &[7; 33]).is_err());
      }
    }
  }

  #[test]
  fn whisper_bytes_match_wacore_libsignal() {
    use wacore_libsignal::protocol::{IdentityKey, PublicKey, SignalMessage};

    let (alice, _) = crate::curve::create_key_pair_int([1; 32]);
    let (bob, _) = crate::curve::create_key_pair_int([2; 32]);
    let (ephemeral, _) = crate::curve::create_key_pair_int([3; 32]);
    let sender = IdentityKey::decode(&alice).unwrap();
    let receiver = IdentityKey::decode(&bob).unwrap();
    for (len, counter) in [
      (0, 0),
      (1, 127),
      (127, 128),
      (128, 16384),
      (65536, u32::MAX),
    ] {
      let msg = WhisperMessage {
        ephemeral_key: Some(ephemeral.to_vec()),
        counter: Some(counter),
        previous_counter: Some(counter),
        ciphertext: Some(vec![0xa5; len]),
      };
      let reference = SignalMessage::new(
        3,
        &[4; 32],
        PublicKey::deserialize(&ephemeral).unwrap(),
        counter,
        counter,
        msg.ciphertext.as_deref().unwrap(),
        &sender,
        &receiver,
      )
      .unwrap();
      let wire = encode_whisper(&msg, &[4; 32], &alice, &bob);
      assert_eq!(wire, reference.serialized());
      assert!(SignalMessage::try_from(wire.as_slice())
        .unwrap()
        .verify_mac(&sender, &receiver, &[4; 32])
        .unwrap());
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
