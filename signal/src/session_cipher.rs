use rand::{rngs::OsRng, RngCore};
use signal_proto::signal::session::{
  Chain, ChainKey, CurrentRatchet, KeyPair, SessionEntry, SessionRecord,
};
use signal_proto::signal::wire::{PreKeyWhisperMessage, WhisperMessage};
use zeroize::Zeroizing;

use crate::crypto::{aes_cbc_decrypt, aes_cbc_encrypt, derive_secrets, CryptoError};
use crate::curve::{create_key_pair_int, scalar_multiply};

use crate::session_record::{now_ms, SessionEntryExt, SessionError, SessionRecordExt};
use crate::wire::{decode_whisper, encode_prekey_whisper, encode_whisper, WireError};

pub const MAX_FUTURE_MESSAGES: i64 = 2000;
pub const CHAIN_SENDING: i32 = 1;
pub const CHAIN_RECEIVING: i32 = 2;

const MESSAGE_KEYS_INFO: &[u8] = b"WhisperMessageKeys";
const RATCHET_INFO: &[u8] = b"WhisperRatchet";
const ZERO_SALT: [u8; 32] = [0u8; 32];

pub const MAX_CLOSED_RECEIVER_CHAINS: usize = 5;
#[derive(Debug, thiserror::Error)]
pub enum CipherError {
  #[error(transparent)]
  Session(#[from] SessionError),
  #[error(transparent)]
  Wire(#[from] WireError),
  #[error(transparent)]
  Crypto(#[from] CryptoError),
  #[error("{0}")]
  Curve(String),
  #[error("No open session")]
  NoOpenSession,
  #[error("No sessions available")]
  NoSessions,
  #[error("No matching sessions found for message")]
  NoMatchingSessions,
  #[error("Key used already or never filled")]
  MessageCounter,
  #[error("Over 2000 messages into the future!")]
  TooFarInFuture,
  #[error("Chain closed")]
  ChainClosed,
  #[error("Tried to decrypt on a sending chain")]
  DecryptOnSendingChain,
  #[error("Tried to encrypt on a receiving chain")]
  EncryptOnReceivingChain,
  #[error("Corrupt session: {0}")]
  Corrupt(&'static str),
}

pub struct EncryptOut {
  /// 1 = WhisperMessage, 3 = PreKeyWhisperMessage
  pub msg_type: u8,
  pub body: Vec<u8>,
  pub registration_id: u32,
}
fn prune_closed_chains(entry: &mut SessionEntry) {
  while entry.closed_chains.len() > MAX_CLOSED_RECEIVER_CHAINS {
    let old = entry.closed_chains.remove(0);
    let _ = entry.delete_chain(&old);
  }
}
fn drop_legacy_dead_chains(entry: &mut SessionEntry) {
  if !entry.closed_chains.is_empty() || entry.chains.len() <= MAX_CLOSED_RECEIVER_CHAINS + 2 {
    return;
  }
  entry.chains.retain(|_, c| {
    c.chain_type != CHAIN_RECEIVING
      || !c.message_keys.is_empty()
      || c.chain_key.as_ref().is_some_and(|k| !k.key.is_empty())
  });
}
fn new_ephemeral_key_pair() -> KeyPair {
  let mut seed = [0u8; 32];
  OsRng.fill_bytes(&mut seed);
  let (pub_key, priv_key) = create_key_pair_int(seed);
  KeyPair {
    pub_key: pub_key.to_vec(),
    priv_key: priv_key.to_vec(),
  }
}

fn ratchet_mut(entry: &mut SessionEntry) -> Result<&mut CurrentRatchet, CipherError> {
  entry
    .current_ratchet
    .as_mut()
    .ok_or(CipherError::Corrupt("missing current_ratchet"))
}

fn our_ephemeral_pub(entry: &SessionEntry) -> Result<Vec<u8>, CipherError> {
  entry
    .current_ratchet
    .as_ref()
    .and_then(|r| r.ephemeral_key_pair.as_ref())
    .map(|p| p.pub_key.clone())
    .ok_or(CipherError::Corrupt("missing ephemeral key pair"))
}

fn counter_to_i32(v: u32) -> i32 {
  i32::try_from(v).unwrap_or(i32::MAX)
}

fn fill_message_keys(chain: &mut Chain, counter: i32) -> Result<(), CipherError> {
  let ck = chain
    .chain_key
    .as_mut()
    .ok_or(CipherError::Corrupt("chain without chain_key"))?;
  if ck.counter >= counter {
    return Ok(());
  }
  if i64::from(counter) - i64::from(ck.counter) > MAX_FUTURE_MESSAGES {
    return Err(CipherError::TooFarInFuture);
  }
  if ck.key.is_empty() {
    return Err(CipherError::ChainClosed);
  }
  while ck.counter < counter {
    let message_key = crate::crypto::hmac_sha256(&ck.key, &[1]);
    let next_chain_key = crate::crypto::hmac_sha256(&ck.key, &[2]);
    chain
      .message_keys
      .insert(ck.counter + 1, message_key.to_vec());
    ck.key = next_chain_key.to_vec();
    ck.counter += 1;
  }
  Ok(())
}

pub fn calculate_ratchet(
  entry: &mut SessionEntry,
  remote_key: &[u8],
  sending: bool,
) -> Result<(), CipherError> {
  let ratchet = entry
    .current_ratchet
    .as_ref()
    .ok_or(CipherError::Corrupt("missing current_ratchet"))?;
  let pair = ratchet
    .ephemeral_key_pair
    .as_ref()
    .ok_or(CipherError::Corrupt("missing ephemeral key pair"))?;

  let shared =
    Zeroizing::new(scalar_multiply(&pair.priv_key, remote_key).map_err(CipherError::Curve)?);
  let [new_root, chain_key] = derive_secrets::<2>(&shared[..], &ratchet.root_key, RATCHET_INFO);

  let chain_id = if sending {
    pair.pub_key.clone()
  } else {
    remote_key.to_vec()
  };
  let chain = Chain {
    chain_key: Some(ChainKey {
      counter: -1,
      key: chain_key.to_vec(),
    }),
    chain_type: if sending {
      CHAIN_SENDING
    } else {
      CHAIN_RECEIVING
    },
    message_keys: Default::default(),
  };
  entry.add_chain(&chain_id, chain)?;
  ratchet_mut(entry)?.root_key = new_root.to_vec();
  Ok(())
}

fn maybe_step_ratchet(
  entry: &mut SessionEntry,
  remote_key: &[u8],
  previous_counter: i32,
) -> Result<(), CipherError> {
  if entry.get_chain(remote_key).is_some() {
    return Ok(());
  }

  drop_legacy_dead_chains(entry);

  let last_remote = ratchet_mut(entry)?.last_remote_ephemeral_key.clone();
  let mut closed_prev = false;
  if let Some(prev) = entry.get_chain_mut(&last_remote) {
    fill_message_keys(prev, previous_counter)?;
    if let Some(ck) = prev.chain_key.as_mut() {
      ck.key.clear();
    }
    closed_prev = prev.chain_type == CHAIN_RECEIVING;
  }
  if closed_prev {
    entry.closed_chains.push(last_remote);
    prune_closed_chains(entry);
  }

  calculate_ratchet(entry, remote_key, false)?;

  let our_pub = our_ephemeral_pub(entry)?;
  let old_counter = entry
    .get_chain(&our_pub)
    .and_then(|c| c.chain_key.as_ref())
    .map(|k| k.counter);
  if let Some(counter) = old_counter {
    ratchet_mut(entry)?.previous_counter = counter.max(0) as u32;
    entry.delete_chain(&our_pub)?;
  }

  ratchet_mut(entry)?.ephemeral_key_pair = Some(new_ephemeral_key_pair());
  calculate_ratchet(entry, remote_key, true)?;
  ratchet_mut(entry)?.last_remote_ephemeral_key = remote_key.to_vec();
  Ok(())
}

pub fn decrypt_with_entry(
  entry: &mut SessionEntry,
  our_identity_pub: &[u8],
  buf: &[u8],
) -> Result<Vec<u8>, CipherError> {
  let decoded = decode_whisper(buf)?;
  let msg = &decoded.message;
  let ephemeral = msg
    .ephemeral_key
    .as_deref()
    .ok_or(CipherError::Corrupt("message without ephemeral key"))?;
  let counter = counter_to_i32(msg.counter.unwrap_or(0));
  let previous_counter = counter_to_i32(msg.previous_counter.unwrap_or(0));

  maybe_step_ratchet(entry, ephemeral, previous_counter)?;

  let chain = entry
    .get_chain_mut(ephemeral)
    .ok_or(CipherError::Corrupt("chain missing after ratchet step"))?;
  if chain.chain_type == CHAIN_SENDING {
    return Err(CipherError::DecryptOnSendingChain);
  }
  fill_message_keys(chain, counter)?;
  let message_key = Zeroizing::new(
    chain
      .message_keys
      .remove(&counter)
      .ok_or(CipherError::MessageCounter)?,
  );

  let [cipher_key, mac_key, iv_block] =
    derive_secrets::<3>(&message_key[..], &ZERO_SALT, MESSAGE_KEYS_INFO);

  let remote_identity = &entry
    .index_info
    .as_ref()
    .ok_or(SessionError::MissingIndexInfo)?
    .remote_identity_key;

  decoded.verify_mac(&mac_key, remote_identity, our_identity_pub)?;

  let plaintext = aes_cbc_decrypt(
    &cipher_key,
    &iv_block[..16],
    msg.ciphertext.as_deref().unwrap_or_default(),
  )?;

  entry.pending_pre_key = None;
  Ok(plaintext)
}

fn decrypt_whisper_impl(
  record: &mut SessionRecord,
  our_identity_pub: &[u8],
  buf: &[u8],
  keep_record_on_err: bool,
) -> Result<Vec<u8>, CipherError> {
  let mut order: Vec<(String, i64)> = record
    .sessions
    .iter()
    .map(|(id, s)| (id.clone(), s.used()))
    .collect();
  if order.is_empty() {
    return Err(CipherError::NoSessions);
  }
  order.sort_by_key(|(_, used)| std::cmp::Reverse(*used));

  let last = order.len() - 1;
  for (i, (id, _)) in order.into_iter().enumerate() {
    let Some(slot) = record.sessions.get_mut(&id) else {
      continue;
    };
    let result = if keep_record_on_err || i != last {
      let mut attempt = slot.clone();
      decrypt_with_entry(&mut attempt, our_identity_pub, buf).map(|pt| {
        *slot = attempt;
        pt
      })
    } else {
      decrypt_with_entry(slot, our_identity_pub, buf)
    };
    match result {
      Ok(plaintext) => {
        if let Some(info) = slot.index_info.as_mut() {
          info.used = now_ms();
        }
        return Ok(plaintext);
      }
      Err(CipherError::MessageCounter) => return Err(CipherError::MessageCounter),
      Err(_) => continue,
    }
  }
  Err(CipherError::NoMatchingSessions)
}

pub fn decrypt_whisper_message(
  record: &mut SessionRecord,
  our_identity_pub: &[u8],
  buf: &[u8],
) -> Result<Vec<u8>, CipherError> {
  decrypt_whisper_impl(record, our_identity_pub, buf, true)
}

pub fn decrypt_whisper_message_consume(
  record: &mut SessionRecord,
  our_identity_pub: &[u8],
  buf: &[u8],
) -> Result<Vec<u8>, CipherError> {
  decrypt_whisper_impl(record, our_identity_pub, buf, false)
}
pub fn encrypt(
  record: &mut SessionRecord,
  our_identity_pub: &[u8],
  our_registration_id: u32,
  plaintext: &[u8],
) -> Result<EncryptOut, CipherError> {
  let entry = record
    .get_open_session_mut()
    .ok_or(CipherError::NoOpenSession)?;

  let our_ephemeral = our_ephemeral_pub(entry)?;
  let previous_counter = entry
    .current_ratchet
    .as_ref()
    .map_or(0, |r| r.previous_counter);
  let remote_identity = entry
    .index_info
    .as_ref()
    .ok_or(SessionError::MissingIndexInfo)?
    .remote_identity_key
    .clone();

  let chain = entry
    .get_chain_mut(&our_ephemeral)
    .ok_or(CipherError::Corrupt("missing sending chain"))?;
  if chain.chain_type == CHAIN_RECEIVING {
    return Err(CipherError::EncryptOnReceivingChain);
  }
  let next = chain
    .chain_key
    .as_ref()
    .ok_or(CipherError::Corrupt("chain without chain_key"))?
    .counter
    + 1;
  fill_message_keys(chain, next)?;
  let counter = chain.chain_key.as_ref().map_or(next, |k| k.counter);
  let message_key = Zeroizing::new(
    chain
      .message_keys
      .remove(&counter)
      .ok_or(CipherError::Corrupt("message key not derived"))?,
  );

  let [cipher_key, mac_key, iv_block] =
    derive_secrets::<3>(&message_key[..], &ZERO_SALT, MESSAGE_KEYS_INFO);
  let ciphertext = aes_cbc_encrypt(&cipher_key, &iv_block[..16], plaintext)?;

  let whisper = WhisperMessage {
    ephemeral_key: Some(our_ephemeral),
    counter: Some(counter as u32),
    previous_counter: Some(previous_counter),
    ciphertext: Some(ciphertext),
  };
  let body = encode_whisper(&whisper, &mac_key, our_identity_pub, &remote_identity);

  let (msg_type, body) = match entry.pending_pre_key.as_ref() {
    Some(pending) => {
      let prekey = PreKeyWhisperMessage {
        registration_id: Some(our_registration_id),
        pre_key_id: pending.pre_key_id,
        signed_pre_key_id: Some(pending.signed_pre_key_id),
        base_key: Some(pending.base_key.clone()),
        identity_key: Some(our_identity_pub.to_vec()),
        message: Some(body),
      };
      (3u8, encode_prekey_whisper(&prekey))
    }
    None => (1u8, body),
  };

  Ok(EncryptOut {
    msg_type,
    body,
    registration_id: entry.registration_id,
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::session_record::{BASE_KEY_OURS, BASE_KEY_THEIRS};
  use signal_proto::signal::session::SessionIndexInfo;

  const ALICE_ID: [u8; 33] = [9; 33];
  const BOB_ID: [u8; 33] = [7; 33];

  fn kp(seed: u8) -> KeyPair {
    let (p, s) = create_key_pair_int([seed; 32]);
    KeyPair {
      pub_key: p.to_vec(),
      priv_key: s.to_vec(),
    }
  }

  fn pair() -> (SessionRecord, SessionRecord) {
    let root = [0x42u8; 32];
    let a_eph = kp(1);
    let b_signed = kp(2);

    let mut alice = SessionEntry {
      registration_id: 2,
      current_ratchet: Some(CurrentRatchet {
        ephemeral_key_pair: Some(a_eph.clone()),
        last_remote_ephemeral_key: b_signed.pub_key.clone(),
        previous_counter: 0,
        root_key: root.to_vec(),
      }),
      index_info: Some(SessionIndexInfo {
        base_key: a_eph.pub_key.clone(),
        base_key_type: BASE_KEY_OURS,
        remote_identity_key: BOB_ID.to_vec(),
        ..Default::default()
      }),
      ..Default::default()
    };
    calculate_ratchet(&mut alice, &b_signed.pub_key, true).unwrap();

    let bob = SessionEntry {
      registration_id: 1,
      current_ratchet: Some(CurrentRatchet {
        ephemeral_key_pair: Some(b_signed),
        last_remote_ephemeral_key: vec![],
        previous_counter: 0,
        root_key: root.to_vec(),
      }),
      index_info: Some(SessionIndexInfo {
        base_key: a_eph.pub_key.clone(),
        base_key_type: BASE_KEY_THEIRS,
        remote_identity_key: ALICE_ID.to_vec(),
        ..Default::default()
      }),
      ..Default::default()
    };

    let mut ra = SessionRecord::new();
    ra.set_session(alice).unwrap();
    let mut rb = SessionRecord::new();
    rb.set_session(bob).unwrap();
    (ra, rb)
  }

  fn send(r: &mut SessionRecord, id: &[u8], msg: &[u8]) -> Vec<u8> {
    let out = encrypt(r, id, 1, msg).unwrap();
    assert_eq!(out.msg_type, 1);
    out.body
  }

  fn recv(r: &mut SessionRecord, id: &[u8], body: &[u8]) -> Result<Vec<u8>, CipherError> {
    decrypt_whisper_message(r, id, body)
  }

  #[test]
  fn roundtrip_both_directions() {
    let (mut a, mut b) = pair();
    for i in 0..5u8 {
      let m = send(&mut a, &ALICE_ID, &[i; 10]);
      assert_eq!(recv(&mut b, &BOB_ID, &m).unwrap(), vec![i; 10]);
      let r = send(&mut b, &BOB_ID, &[i + 100; 3]);
      assert_eq!(recv(&mut a, &ALICE_ID, &r).unwrap(), vec![i + 100; 3]);
    }
  }

  #[test]
  fn out_of_order_and_replay() {
    let (mut a, mut b) = pair();
    let m0 = send(&mut a, &ALICE_ID, b"zero");
    let m1 = send(&mut a, &ALICE_ID, b"one");
    let m2 = send(&mut a, &ALICE_ID, b"two");

    assert_eq!(recv(&mut b, &BOB_ID, &m2).unwrap(), b"two");
    assert_eq!(recv(&mut b, &BOB_ID, &m0).unwrap(), b"zero");
    assert_eq!(recv(&mut b, &BOB_ID, &m1).unwrap(), b"one");
    assert!(matches!(
      recv(&mut b, &BOB_ID, &m1),
      Err(CipherError::MessageCounter)
    ));
  }

  #[test]
  fn late_message_from_previous_chain() {
    let (mut a, mut b) = pair();
    let a0 = send(&mut a, &ALICE_ID, b"a0");
    let a1 = send(&mut a, &ALICE_ID, b"a1");
    assert_eq!(recv(&mut b, &BOB_ID, &a0).unwrap(), b"a0");

    let b0 = send(&mut b, &BOB_ID, b"b0");
    assert_eq!(recv(&mut a, &ALICE_ID, &b0).unwrap(), b"b0");

    let a2 = send(&mut a, &ALICE_ID, b"a2");
    assert_eq!(recv(&mut b, &BOB_ID, &a2).unwrap(), b"a2");
    assert_eq!(recv(&mut b, &BOB_ID, &a1).unwrap(), b"a1");
  }

  #[test]
  fn failed_attempt_leaves_record_untouched() {
    let (mut a, mut b) = pair();
    let mut m = send(&mut a, &ALICE_ID, b"x");
    let last = m.len() - 1;
    m[last] ^= 1;

    let before = b.clone();
    assert!(matches!(
      recv(&mut b, &BOB_ID, &m),
      Err(CipherError::NoMatchingSessions)
    ));
    assert_eq!(b, before, "un intento fallido no debe mutar la sesión");

    m[last] ^= 1;
    assert_eq!(recv(&mut b, &BOB_ID, &m).unwrap(), b"x");
  }

  #[test]
  fn wrong_local_identity_fails_mac() {
    let (mut a, mut b) = pair();
    let m = send(&mut a, &ALICE_ID, b"x");
    assert!(matches!(
      recv(&mut b, &[1u8; 33], &m),
      Err(CipherError::NoMatchingSessions)
    ));
  }

  #[test]
  fn no_sessions_and_no_open_session() {
    let mut empty = SessionRecord::new();
    assert!(matches!(
      encrypt(&mut empty, &ALICE_ID, 1, b"x"),
      Err(CipherError::NoOpenSession)
    ));
    assert!(matches!(
      decrypt_whisper_message(&mut empty, &BOB_ID, &[0x33; 20]),
      Err(CipherError::NoSessions)
    ));
  }

  #[test]
  fn fill_message_keys_limit() {
    let mut chain = Chain {
      chain_key: Some(ChainKey {
        counter: -1,
        key: vec![1u8; 32],
      }),
      chain_type: CHAIN_RECEIVING,
      message_keys: Default::default(),
    };
    assert!(matches!(
      fill_message_keys(&mut chain, 2001),
      Err(CipherError::TooFarInFuture)
    ));
    assert!(chain.message_keys.is_empty());
    fill_message_keys(&mut chain, 1999).unwrap();
    assert_eq!(chain.message_keys.len(), 2000);
  }

  #[test]
  fn closed_chain_cannot_be_extended() {
    let mut chain = Chain {
      chain_key: Some(ChainKey {
        counter: 3,
        key: vec![],
      }),
      chain_type: CHAIN_RECEIVING,
      message_keys: Default::default(),
    };
    assert!(matches!(
      fill_message_keys(&mut chain, 5),
      Err(CipherError::ChainClosed)
    ));
    assert!(fill_message_keys(&mut chain, 3).is_ok());
  }
}
