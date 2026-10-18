use prost::Message;
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

use crate::crypto::{aes_cbc_decrypt, aes_cbc_encrypt, derive_secrets, hmac_sha256, CryptoError};
use crate::curve::{create_key_pair_int, sign, verify};
use crate::wire::{version_ok, VERSION_BYTE};
use signal_proto::signal::group_wire::{
  SenderChainKey, SenderKeyDistributionMessage, SenderKeyMessage, SenderKeyRecordStructure,
  SenderKeyStateStructure, SenderMessageKey, SenderSigningKey,
};

pub type SenderKeyRecord = SenderKeyRecordStructure;

pub const MAX_STATES: usize = 5;
pub const MAX_MESSAGE_KEYS: usize = 2000;
pub const MAX_FUTURE_MESSAGES: u32 = 2000;
pub const SIGNATURE_LEN: usize = 64;

const GROUP_INFO: &[u8] = b"WhisperGroup";

#[derive(Debug, thiserror::Error)]
pub enum GroupError {
  #[error("No session to encrypt message")]
  NoSession,
  #[error("No session found to decrypt message")]
  NoStateForDecrypt,
  #[error("Invalid signature!")]
  InvalidSignature,
  #[error("Received message with old counter: {current}, {iteration}")]
  OldCounter { current: u32, iteration: u32 },
  #[error("Over 2000 messages into the future!")]
  TooFarInFuture,
  #[error("InvalidMessageException")]
  InvalidMessage,
  #[error("Incompatible version number on SenderKeyMessage")]
  IncompatibleVersion,
  #[error("Message too short")]
  TooShort,
  #[error("Malformed sender key message: missing {0}")]
  Malformed(&'static str),
  #[error("Invalid {0}")]
  InvalidKey(&'static str),
  #[error("Corrupt sender key state: {0}")]
  Corrupt(&'static str),
  #[error("{0}")]
  Curve(String),
  #[error("protobuf: {0}")]
  Decode(#[from] prost::DecodeError),
  #[error(transparent)]
  Crypto(#[from] CryptoError),
}

pub fn serialize_record(record: &SenderKeyRecord) -> Vec<u8> {
  record.encode_to_vec()
}

pub fn deserialize_record(buf: &[u8]) -> Result<SenderKeyRecord, GroupError> {
  Ok(SenderKeyRecord::decode(buf)?)
}

struct MessageKeyMaterial {
  iv: [u8; 16],
  key: Zeroizing<[u8; 32]>,
}

fn material_from_seed(seed: &[u8]) -> MessageKeyMaterial {
  let [d0, d1] = derive_secrets::<2>(seed, &[0u8; 32], GROUP_INFO);
  let mut iv = [0u8; 16];
  iv.copy_from_slice(&d0[..16]);
  let mut key = Zeroizing::new([0u8; 32]);
  key[..16].copy_from_slice(&d0[16..]);
  key[16..].copy_from_slice(&d1[..16]);
  MessageKeyMaterial { iv, key }
}

/// (iteration, seed) de la chain key del estado.
fn chain_parts(state: &SenderKeyStateStructure) -> Result<(u32, &[u8]), GroupError> {
  let chain = state
    .sender_chain_key
    .as_ref()
    .ok_or(GroupError::Corrupt("state without chain key"))?;
  let seed = chain
    .seed
    .as_deref()
    .ok_or(GroupError::Corrupt("chain key without seed"))?;
  Ok((chain.iteration.unwrap_or(0), seed))
}

fn push_skipped(state: &mut SenderKeyStateStructure, iteration: u32, seed: Vec<u8>) {
  state.sender_message_keys.push(SenderMessageKey {
    iteration: Some(iteration),
    seed: Some(seed),
  });
  if state.sender_message_keys.len() > MAX_MESSAGE_KEYS {
    state.sender_message_keys.remove(0);
  }
}

fn get_sender_key(
  state: &mut SenderKeyStateStructure,
  iteration: u32,
) -> Result<MessageKeyMaterial, GroupError> {
  let (mut current, chain_seed) = chain_parts(state)?;
  let mut seed = Zeroizing::new(chain_seed.to_vec());

  if current > iteration {
    return match state
      .sender_message_keys
      .iter()
      .position(|k| k.iteration == Some(iteration))
    {
      Some(pos) => {
        let k = state.sender_message_keys.remove(pos);
        let seed = Zeroizing::new(
          k.seed
            .ok_or(GroupError::Corrupt("message key without seed"))?,
        );
        Ok(material_from_seed(&seed))
      }
      None => Err(GroupError::OldCounter { current, iteration }),
    };
  }
  if iteration - current > MAX_FUTURE_MESSAGES {
    return Err(GroupError::TooFarInFuture);
  }
  while current < iteration {
    push_skipped(state, current, hmac_sha256(&seed, &[0x01]).to_vec());
    seed = Zeroizing::new(hmac_sha256(&seed, &[0x02]).to_vec());
    current += 1;
  }
  let message_seed = Zeroizing::new(hmac_sha256(&seed, &[0x01]));
  let next = current.checked_add(1).ok_or(GroupError::TooFarInFuture)?;
  state.sender_chain_key = Some(SenderChainKey {
    iteration: Some(next),
    seed: Some(hmac_sha256(&seed, &[0x02]).to_vec()),
  });
  Ok(material_from_seed(&message_seed[..]))
}

fn normalize_signing_public(key: &[u8]) -> Result<Vec<u8>, GroupError> {
  match key.len() {
    32 => {
      let mut v = Vec::with_capacity(33);
      v.push(0x05);
      v.extend_from_slice(key);
      Ok(v)
    }
    33 if key[0] == 0x05 => Ok(key.to_vec()),
    _ => Err(GroupError::InvalidKey("signing key")),
  }
}

fn signing_public(state: &SenderKeyStateStructure) -> Result<Vec<u8>, GroupError> {
  let public = state
    .sender_signing_key
    .as_ref()
    .and_then(|k| k.public.as_deref())
    .ok_or(GroupError::Corrupt("state without signing key"))?;
  normalize_signing_public(public)
}

fn with_version(msg: &impl Message) -> Vec<u8> {
  let mut out = vec![VERSION_BYTE];
  out.extend_from_slice(&msg.encode_to_vec());
  out
}

pub fn create_distribution_message(record: &mut SenderKeyRecord) -> Result<Vec<u8>, GroupError> {
  let mut chain_seed = Zeroizing::new([0u8; 32]);
  let mut signing_seed = Zeroizing::new([0u8; 32]);
  OsRng.fill_bytes(&mut chain_seed[..]);
  OsRng.fill_bytes(&mut signing_seed[..]);
  let key_id = 1 + OsRng.next_u32() % 0x7fff_fffe; // 31 bits
  create_distribution_message_with(record, key_id, &chain_seed, &signing_seed)
}

pub(crate) fn create_distribution_message_with(
  record: &mut SenderKeyRecord,
  key_id: u32,
  chain_seed: &[u8; 32],
  signing_seed: &[u8; 32],
) -> Result<Vec<u8>, GroupError> {
  if record.sender_key_states.is_empty() {
    let (public, private) = create_key_pair_int(*signing_seed);
    record.sender_key_states.push(SenderKeyStateStructure {
      sender_key_id: Some(key_id),
      sender_chain_key: Some(SenderChainKey {
        iteration: Some(0),
        seed: Some(chain_seed.to_vec()),
      }),
      sender_signing_key: Some(SenderSigningKey {
        public: Some(public.to_vec()),
        private: Some(private.to_vec()),
      }),
      sender_message_keys: Vec::new(),
    });
  }
  let state = record
    .sender_key_states
    .last()
    .ok_or(GroupError::NoSession)?;
  let (iteration, seed) = chain_parts(state)?;
  let msg = SenderKeyDistributionMessage {
    id: state.sender_key_id,
    iteration: Some(iteration),
    chain_key: Some(seed.to_vec()),
    signing_key: Some(signing_public(state)?),
  };
  Ok(with_version(&msg))
}

fn add_sender_key_state(record: &mut SenderKeyRecord, new_state: SenderKeyStateStructure) {
  let public =
    |s: &SenderKeyStateStructure| s.sender_signing_key.as_ref().and_then(|k| k.public.clone());
  let new_public = public(&new_state);
  if let Some(pos) = record
    .sender_key_states
    .iter()
    .position(|s| s.sender_key_id == new_state.sender_key_id && public(s) == new_public)
  {
    let existing = record.sender_key_states.remove(pos);
    record.sender_key_states.push(existing);
    return;
  }
  record.sender_key_states.push(new_state);
  if record.sender_key_states.len() > MAX_STATES {
    record.sender_key_states.remove(0);
  }
}

pub fn process_distribution_message(
  record: &mut SenderKeyRecord,
  buf: &[u8],
) -> Result<(), GroupError> {
  if buf.is_empty() {
    return Err(GroupError::TooShort);
  }
  if !version_ok(buf[0]) {
    return Err(GroupError::IncompatibleVersion);
  }
  let m = SenderKeyDistributionMessage::decode(&buf[1..])?;
  let key_id = m.id.ok_or(GroupError::Malformed("id"))?;
  let iteration = m.iteration.ok_or(GroupError::Malformed("iteration"))?;
  let chain_key = m.chain_key.ok_or(GroupError::Malformed("chainKey"))?;
  let signing_key = m.signing_key.ok_or(GroupError::Malformed("signingKey"))?;
  if chain_key.len() != 32 {
    return Err(GroupError::InvalidKey("chain key"));
  }
  add_sender_key_state(
    record,
    SenderKeyStateStructure {
      sender_key_id: Some(key_id),
      sender_chain_key: Some(SenderChainKey {
        iteration: Some(iteration),
        seed: Some(chain_key),
      }),
      sender_signing_key: Some(SenderSigningKey {
        public: Some(normalize_signing_public(&signing_key)?),
        private: None,
      }),
      sender_message_keys: Vec::new(),
    },
  );
  Ok(())
}

pub fn encrypt(
  record: &mut SenderKeyRecord,
  plaintext: &[u8],
  legacy_iterations: bool,
) -> Result<Vec<u8>, GroupError> {
  let state = record
    .sender_key_states
    .last_mut()
    .ok_or(GroupError::NoSession)?;

  let private = state
    .sender_signing_key
    .as_ref()
    .and_then(|k| k.private.as_deref())
    .unwrap_or(&[]);
  let signing_private =
    <[u8; 32]>::try_from(private).map_err(|_| GroupError::InvalidKey("signing private key"))?;

  let (current, _) = chain_parts(state)?;
  let target = if legacy_iterations && current != 0 {
    current.checked_add(1).ok_or(GroupError::TooFarInFuture)?
  } else {
    current
  };

  let material = get_sender_key(state, target)?;
  let ciphertext = aes_cbc_encrypt(&material.key[..], &material.iv, plaintext)?;
  let msg = SenderKeyMessage {
    id: state.sender_key_id,
    iteration: Some(target),
    ciphertext: Some(ciphertext),
  };
  let mut out = with_version(&msg);
  let signature = sign(&signing_private, &out, None).map_err(GroupError::Curve)?;
  out.extend_from_slice(&signature);
  Ok(out)
}

pub fn encrypt_group_message(
  record: &mut SenderKeyRecord,
  plaintext: &[u8],
  legacy_iterations: bool,
) -> Result<(Vec<u8>, Vec<u8>), GroupError> {
  let skdm = create_distribution_message(record)?;
  let ciphertext = encrypt(record, plaintext, legacy_iterations)?;
  Ok((ciphertext, skdm))
}

struct ParsedMessage<'a> {
  signed: &'a [u8],
  signature: &'a [u8],
  key_id: u32,
  iteration: u32,
  ciphertext: Vec<u8>,
}

fn parse_sender_key_message(buf: &[u8]) -> Result<ParsedMessage<'_>, GroupError> {
  if buf.len() < 1 + SIGNATURE_LEN {
    return Err(GroupError::TooShort);
  }
  if !version_ok(buf[0]) {
    return Err(GroupError::IncompatibleVersion);
  }
  let split = buf.len() - SIGNATURE_LEN;
  let m = SenderKeyMessage::decode(&buf[1..split])?;
  Ok(ParsedMessage {
    signed: &buf[..split],
    signature: &buf[split..],
    key_id: m.id.ok_or(GroupError::Malformed("id"))?,
    iteration: m.iteration.ok_or(GroupError::Malformed("iteration"))?,
    ciphertext: m.ciphertext.ok_or(GroupError::Malformed("ciphertext"))?,
  })
}

pub fn decrypt(record: &mut SenderKeyRecord, buf: &[u8]) -> Result<Vec<u8>, GroupError> {
  let msg = parse_sender_key_message(buf)?;

  let mut candidate_seen = false;
  let mut found = None;
  for (i, state) in record.sender_key_states.iter().enumerate() {
    if state.sender_key_id != Some(msg.key_id) {
      continue;
    }
    candidate_seen = true;
    let public = signing_public(state)?;
    if verify(&public, msg.signed, msg.signature).map_err(GroupError::Curve)? {
      found = Some(i);
      break;
    }
  }
  let Some(index) = found else {
    return Err(if candidate_seen {
      GroupError::InvalidSignature
    } else {
      GroupError::NoStateForDecrypt
    });
  };

  let mut attempt = record.sender_key_states[index].clone();
  let material = get_sender_key(&mut attempt, msg.iteration)?;
  let plaintext = aes_cbc_decrypt(&material.key[..], &material.iv, &msg.ciphertext)
    .map_err(|_| GroupError::InvalidMessage)?;
  record.sender_key_states[index] = attempt;
  Ok(plaintext)
}
