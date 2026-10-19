use rand::{rngs::OsRng, RngCore};
use signal_proto::signal::session::{
  CurrentRatchet, KeyPair, PendingPreKey, SessionEntry, SessionIndexInfo, SessionRecord,
};
use signal_proto::signal::wire::PreKeyWhisperMessage;
use zeroize::Zeroizing;

use crate::crypto::derive_secrets;
use crate::curve::{create_key_pair_int, scalar_multiply, verify};
use crate::session_cipher::{calculate_ratchet, decrypt_with_entry, CipherError};
use crate::session_record::{
  now_ms, SessionEntryExt, SessionError, SessionRecordExt, BASE_KEY_OURS, BASE_KEY_THEIRS,
};
use crate::wire::{decode_prekey_whisper, WireError};

#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
  #[error(transparent)]
  Cipher(#[from] CipherError),
  #[error(transparent)]
  Session(#[from] SessionError),
  #[error(transparent)]
  Wire(#[from] WireError),
  #[error("{0}")]
  Curve(String),
  #[error("Invalid {0}")]
  InvalidKey(&'static str),
  #[error("Invalid signature")]
  InvalidSignature,
  #[error("Identity public key does not match its private key")]
  IdentityMismatch,
  #[error("Signed prekey public key does not match its private key")]
  SignedPreKeyMismatch,
  #[error("PreKey public key does not match its private key")]
  PreKeyMismatch,
  #[error("Invalid PreKey ID")]
  InvalidPreKeyId,
  #[error("Malformed PreKeyWhisperMessage: missing {0}")]
  Malformed(&'static str),
}
const IDENTITY_FIELD: u64 = 3;
pub struct LocalIdentity<'a> {
  pub priv_key: &'a [u8],
  pub pub_key: &'a [u8],
}

pub struct KeyPairRef<'a> {
  pub pub_key: &'a [u8],
  pub priv_key: &'a [u8],
}

pub struct RemoteBundle<'a> {
  pub registration_id: u32,
  pub identity_key: &'a [u8],
  pub signed_pre_key_id: u32,
  pub signed_pre_key: &'a [u8],
  pub signed_pre_key_signature: &'a [u8],
  pub pre_key: Option<(u32, &'a [u8])>,
}

pub struct IncomingKeys<'a> {
  pub identity: LocalIdentity<'a>,
  pub signed_pre_key: KeyPairRef<'a>,
  pub pre_key: Option<KeyPairRef<'a>>,
}

pub struct PreKeyDecrypt {
  pub plaintext: Vec<u8>,

  pub used_pre_key_id: Option<u32>,
}

fn check_pub33(key: &[u8], what: &'static str) -> Result<(), BuilderError> {
  if key.len() == 33 && key[0] == 0x05 {
    Ok(())
  } else {
    Err(BuilderError::InvalidKey(what))
  }
}

fn check_pair(priv_key: &[u8], pub_key: &[u8], err: BuilderError) -> Result<(), BuilderError> {
  let seed = <[u8; 32]>::try_from(priv_key).map_err(|_| BuilderError::InvalidKey("private key"))?;
  let (derived, _) = create_key_pair_int(seed);
  if derived.as_slice() == pub_key {
    Ok(())
  } else {
    Err(err)
  }
}

fn pair_from_seed(seed: [u8; 32]) -> KeyPair {
  let (pub_key, priv_key) = create_key_pair_int(seed);
  KeyPair {
    pub_key: pub_key.to_vec(),
    priv_key: priv_key.to_vec(),
  }
}

fn dh(priv_key: &[u8], pub_key: &[u8]) -> Result<Zeroizing<[u8; 32]>, BuilderError> {
  scalar_multiply(priv_key, pub_key)
    .map(Zeroizing::new)
    .map_err(BuilderError::Curve)
}

fn shared_secret(parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
  let mut v = Zeroizing::new(Vec::with_capacity(32 * (parts.len() + 1)));
  v.extend_from_slice(&[0xffu8; 32]);
  for p in parts {
    v.extend_from_slice(p);
  }
  v
}
fn zero_bits(n: usize) -> Zeroizing<Vec<u8>> {
  let mut v = Zeroizing::new(Vec::with_capacity(n));
  v.resize(n, 0u8);
  v
}

fn derive_root(shared: &[u8]) -> Zeroizing<[u8; 32]> {
  let [root] = derive_secrets::<1>(shared, &zero_bits(32), b"WhisperText");
  Zeroizing::new(root)
}

fn install(record: &mut SessionRecord, entry: SessionEntry) -> Result<(), BuilderError> {
  if let Some(open) = record.get_open_session_mut() {
    open.close();
  }
  record.set_session(entry)?;
  record.remove_old_sessions()?;
  Ok(())
}

pub fn process_prekey_bundle(
  record: &mut SessionRecord,
  our: &LocalIdentity,
  bundle: &RemoteBundle,
) -> Result<(), BuilderError> {
  let mut base_seed = Zeroizing::new([0u8; 32]);
  let mut ratchet_seed = Zeroizing::new([0u8; 32]);
  OsRng.fill_bytes(&mut base_seed[..]);
  OsRng.fill_bytes(&mut ratchet_seed[..]);
  process_prekey_bundle_with_keys(record, our, bundle, &base_seed, &ratchet_seed)
}

pub(crate) fn process_prekey_bundle_with_keys(
  record: &mut SessionRecord,
  our: &LocalIdentity,
  bundle: &RemoteBundle,
  base_seed: &[u8; 32],
  ratchet_seed: &[u8; 32],
) -> Result<(), BuilderError> {
  check_pub33(our.pub_key, "our identity key")?;
  check_pub33(bundle.identity_key, "remote identity key")?;
  check_pub33(bundle.signed_pre_key, "signed prekey")?;
  if let Some((_, pk)) = bundle.pre_key {
    check_pub33(pk, "prekey")?;
  }
  if bundle.signed_pre_key_signature.len() != 64 {
    return Err(BuilderError::InvalidKey("signature"));
  }
  check_pair(our.priv_key, our.pub_key, BuilderError::IdentityMismatch)?;

  let ok = verify(
    bundle.identity_key,
    bundle.signed_pre_key,
    bundle.signed_pre_key_signature,
  )
  .map_err(BuilderError::Curve)?;
  if !ok {
    return Err(BuilderError::InvalidSignature);
  }

  let base = pair_from_seed(*base_seed);

  let a1 = dh(our.priv_key, bundle.signed_pre_key)?; // DH(IK_A, SPK_B)
  let a2 = dh(&base.priv_key, bundle.identity_key)?; // DH(EK_A, IK_B)
  let a3 = dh(&base.priv_key, bundle.signed_pre_key)?; // DH(EK_A, SPK_B)
  let a4 = match bundle.pre_key {
    Some((_, pk)) => Some(dh(&base.priv_key, pk)?), // DH(EK_A, OPK_B)
    None => None,
  };
  let mut parts: Vec<&[u8]> = vec![&a1[..], &a2[..], &a3[..]];
  if let Some(a4) = a4.as_ref() {
    parts.push(&a4[..]);
  }
  let root = derive_root(&shared_secret(&parts));

  let now = now_ms();
  let mut entry = SessionEntry {
    registration_id: bundle.registration_id,
    current_ratchet: Some(CurrentRatchet {
      ephemeral_key_pair: Some(pair_from_seed(*ratchet_seed)),
      last_remote_ephemeral_key: bundle.signed_pre_key.to_vec(),
      previous_counter: 0,
      root_key: root.to_vec(),
    }),
    index_info: Some(SessionIndexInfo {
      base_key: base.pub_key.clone(),
      base_key_type: BASE_KEY_OURS,
      is_closed: false,
      closed_at: 0,
      used: now,
      created: now,
      remote_identity_key: bundle.identity_key.to_vec(),
    }),
    chains: Default::default(),
    pending_pre_key: Some(PendingPreKey {
      base_key: base.pub_key,
      pre_key_id: bundle.pre_key.map(|(id, _)| id),
      signed_pre_key_id: bundle.signed_pre_key_id,
    }),
  };

  calculate_ratchet(&mut entry, bundle.signed_pre_key, true)?;
  install(record, entry)
}

pub fn init_incoming(
  record: &mut SessionRecord,
  keys: &IncomingKeys,
  msg: &PreKeyWhisperMessage,
) -> Result<Option<u32>, BuilderError> {
  let base_key = msg
    .base_key
    .as_deref()
    .ok_or(BuilderError::Malformed("baseKey"))?;
  let identity_key = msg
    .identity_key
    .as_deref()
    .ok_or(BuilderError::Malformed("identityKey"))?;
  check_pub33(base_key, "base key")?;
  check_pub33(identity_key, "remote identity key")?;

  // This just means we haven't replied
  if record.get_session(base_key)?.is_some() {
    return Ok(None);
  }

  if msg.pre_key_id.is_some() && keys.pre_key.is_none() {
    return Err(BuilderError::InvalidPreKeyId);
  }
  let opk = if msg.pre_key_id.is_some() {
    keys.pre_key.as_ref()
  } else {
    None
  };

  check_pub33(keys.identity.pub_key, "our identity key")?;
  check_pub33(keys.signed_pre_key.pub_key, "signed prekey")?;
  check_pair(
    keys.identity.priv_key,
    keys.identity.pub_key,
    BuilderError::IdentityMismatch,
  )?;
  check_pair(
    keys.signed_pre_key.priv_key,
    keys.signed_pre_key.pub_key,
    BuilderError::SignedPreKeyMismatch,
  )?;
  if let Some(k) = opk {
    check_pair(k.priv_key, k.pub_key, BuilderError::PreKeyMismatch)?;
  }

  let a1 = dh(keys.identity.priv_key, base_key)?; // DH(EK_A, IK_B)
  let a2 = dh(keys.signed_pre_key.priv_key, identity_key)?; // DH(IK_A, SPK_B)
  let a3 = dh(keys.signed_pre_key.priv_key, base_key)?; // DH(EK_A, SPK_B)
  let a4 = match opk {
    Some(k) => Some(dh(k.priv_key, base_key)?), // DH(EK_A, OPK_B)
    None => None,
  };
  let mut parts: Vec<&[u8]> = vec![&a2[..], &a1[..], &a3[..]];
  if let Some(a4) = a4.as_ref() {
    parts.push(&a4[..]);
  }
  let root = derive_root(&shared_secret(&parts));

  let now = now_ms();
  let entry = SessionEntry {
    registration_id: msg.registration_id.unwrap_or(0),
    current_ratchet: Some(CurrentRatchet {
      ephemeral_key_pair: Some(KeyPair {
        pub_key: keys.signed_pre_key.pub_key.to_vec(),
        priv_key: keys.signed_pre_key.priv_key.to_vec(),
      }),
      last_remote_ephemeral_key: base_key.to_vec(),
      previous_counter: 0,
      root_key: root.to_vec(),
    }),
    index_info: Some(SessionIndexInfo {
      base_key: base_key.to_vec(),
      base_key_type: BASE_KEY_THEIRS,
      is_closed: false,
      closed_at: 0,
      used: now,
      created: now,
      remote_identity_key: identity_key.to_vec(),
    }),
    chains: Default::default(),
    pending_pre_key: None,
  };
  install(record, entry)?;
  Ok(msg.pre_key_id)
}

#[inline]
fn skip(buf: &[u8], pos: usize, n: usize) -> Option<usize> {
  pos.checked_add(n).filter(|&p| p <= buf.len())
}

fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
  let mut result = 0u64;
  let mut shift = 0u32;
  loop {
    if shift > 63 {
      return None;
    }
    let byte = *buf.get(*pos)?;
    *pos += 1;
    result |= u64::from(byte & 0x7f) << shift;
    if byte & 0x80 == 0 {
      return Some(result);
    }
    shift += 7;
  }
}

fn find_identity(body: &[u8]) -> Option<&[u8]> {
  let mut pos = 0usize;
  let mut found: Option<&[u8]> = None;

  while pos < body.len() {
    let tag = read_varint(body, &mut pos)?;
    let field = tag >> 3;
    match tag & 7 {
      0 => {
        read_varint(body, &mut pos)?;
      }
      1 => pos = skip(body, pos, 8)?,
      5 => pos = skip(body, pos, 4)?,
      2 => {
        let len = usize::try_from(read_varint(body, &mut pos)?).ok()?;
        let end = skip(body, pos, len)?;
        if field == IDENTITY_FIELD {
          found = Some(&body[pos..end]);
        }
        pos = end;
      }
      _ => return None,
    }
  }
  found
}

pub fn extract(ciphertext: &[u8]) -> Option<&[u8]> {
  if ciphertext.len() < 2 || (ciphertext[0] & 0x0f) != 3 {
    return None;
  }
  find_identity(&ciphertext[1..]).filter(|k| k.len() == 33)
}
pub fn decrypt_prekey_message(
  record: &mut SessionRecord,
  keys: &IncomingKeys,
  buf: &[u8],
) -> Result<PreKeyDecrypt, BuilderError> {
  let msg = decode_prekey_whisper(buf)?;
  let inner = msg
    .message
    .as_deref()
    .ok_or(BuilderError::Malformed("message"))?;
  let used_pre_key_id = init_incoming(record, keys, &msg)?;

  let base_key = msg
    .base_key
    .as_deref()
    .ok_or(BuilderError::Malformed("baseKey"))?;
  let slot = record
    .get_session_mut(base_key)
    .ok_or(CipherError::Corrupt("session missing after init_incoming"))?;
  let mut attempt = slot.clone();
  let plaintext = decrypt_with_entry(&mut attempt, keys.identity.pub_key, inner)?;
  *slot = attempt;

  Ok(PreKeyDecrypt {
    plaintext,
    used_pre_key_id,
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::curve::sign;
  use crate::session_cipher::{decrypt_whisper_message, encrypt};

  fn identity(seed: u8) -> (Vec<u8>, Vec<u8>) {
    let (p, s) = create_key_pair_int([seed; 32]);
    (p.to_vec(), s.to_vec())
  }

  struct Bob {
    id_pub: Vec<u8>,
    id_priv: Vec<u8>,
    spk_pub: Vec<u8>,
    spk_priv: Vec<u8>,
    spk_sig: [u8; 64],
    opk_pub: Vec<u8>,
    opk_priv: Vec<u8>,
  }

  fn bob() -> Bob {
    let (id_pub, id_priv) = identity(0x77);
    let (spk_pub, spk_priv) = identity(0x43);
    let (opk_pub, opk_priv) = identity(0x99);
    let spk_sig = sign(&id_priv, &spk_pub, None).unwrap();
    Bob {
      id_pub,
      id_priv,
      spk_pub,
      spk_priv,
      spk_sig,
      opk_pub,
      opk_priv,
    }
  }

  fn bundle(b: &Bob, with_opk: bool) -> RemoteBundle<'_> {
    RemoteBundle {
      registration_id: 22,
      identity_key: &b.id_pub,
      signed_pre_key_id: 3,
      signed_pre_key: &b.spk_pub,
      signed_pre_key_signature: &b.spk_sig,
      pre_key: with_opk.then(|| (7u32, &b.opk_pub[..])),
    }
  }

  fn incoming(b: &Bob, with_opk: bool) -> IncomingKeys<'_> {
    IncomingKeys {
      identity: LocalIdentity {
        priv_key: &b.id_priv,
        pub_key: &b.id_pub,
      },
      signed_pre_key: KeyPairRef {
        pub_key: &b.spk_pub,
        priv_key: &b.spk_priv,
      },
      pre_key: with_opk.then(|| KeyPairRef {
        pub_key: &b.opk_pub,
        priv_key: &b.opk_priv,
      }),
    }
  }

  #[test]
  fn handshake_roundtrip() {
    for with_opk in [false, true] {
      let (a_pub, a_priv) = identity(0x42);
      let alice = LocalIdentity {
        priv_key: &a_priv,
        pub_key: &a_pub,
      };
      let bob = bob();

      let mut ra = SessionRecord::new();
      process_prekey_bundle(&mut ra, &alice, &bundle(&bob, with_opk)).unwrap();

      let first = encrypt(&mut ra, &a_pub, 11, b"hola").unwrap();
      assert_eq!(first.msg_type, 3);
      assert_eq!(first.registration_id, 22);

      let mut rb = SessionRecord::new();
      let got = decrypt_prekey_message(&mut rb, &incoming(&bob, with_opk), &first.body).unwrap();
      assert_eq!(got.plaintext, b"hola");
      assert_eq!(got.used_pre_key_id, if with_opk { Some(7) } else { None });

      let reply = encrypt(&mut rb, &bob.id_pub, 22, b"que tal").unwrap();
      assert_eq!(reply.msg_type, 1);
      assert_eq!(
        decrypt_whisper_message(&mut ra, &a_pub, &reply.body).unwrap(),
        b"que tal"
      );

      let next = encrypt(&mut ra, &a_pub, 11, b"ok").unwrap();
      assert_eq!(next.msg_type, 1);
      assert_eq!(
        decrypt_whisper_message(&mut rb, &bob.id_pub, &next.body).unwrap(),
        b"ok"
      );
    }
  }

  #[test]
  fn repeated_prekey_message_is_idempotent() {
    let (a_pub, a_priv) = identity(0x42);
    let alice = LocalIdentity {
      priv_key: &a_priv,
      pub_key: &a_pub,
    };
    let bob = bob();
    let mut ra = SessionRecord::new();
    process_prekey_bundle(&mut ra, &alice, &bundle(&bob, true)).unwrap();
    let m1 = encrypt(&mut ra, &a_pub, 11, b"one").unwrap();
    let m2 = encrypt(&mut ra, &a_pub, 11, b"two").unwrap();
    assert_eq!((m1.msg_type, m2.msg_type), (3, 3));

    let mut rb = SessionRecord::new();
    let keys = incoming(&bob, true);
    let r2 = decrypt_prekey_message(&mut rb, &keys, &m2.body).unwrap();
    assert_eq!(r2.plaintext, b"two");
    assert_eq!(r2.used_pre_key_id, Some(7));
    let r1 = decrypt_prekey_message(&mut rb, &keys, &m1.body).unwrap();
    assert_eq!(r1.plaintext, b"one");
    assert_eq!(r1.used_pre_key_id, None);
    assert_eq!(rb.sessions.len(), 1);
  }

  #[test]
  fn roles_and_key_separation_are_pinned() {
    let (a_pub, a_priv) = identity(0x42);
    let alice = LocalIdentity {
      priv_key: &a_priv,
      pub_key: &a_pub,
    };
    let bob = bob();
    let mut ra = SessionRecord::new();
    process_prekey_bundle_with_keys(
      &mut ra,
      &alice,
      &bundle(&bob, true),
      &[0x55; 32],
      &[0x56; 32],
    )
    .unwrap();

    let base = pair_from_seed([0x55; 32]);
    let ratchet = pair_from_seed([0x56; 32]);
    let e = ra.sessions.values().next().unwrap();
    let info = e.index_info.as_ref().unwrap();
    let cur = e.current_ratchet.as_ref().unwrap();

    assert_eq!(info.base_key, base.pub_key);
    assert_eq!(info.base_key_type, BASE_KEY_OURS);
    assert_eq!(info.remote_identity_key, bob.id_pub);
    assert_eq!(
      cur.ephemeral_key_pair.as_ref().unwrap().pub_key,
      ratchet.pub_key
    );
    assert_ne!(
      base.pub_key, ratchet.pub_key,
      "base key y clave del ratchet son distintas"
    );
    assert_eq!(cur.last_remote_ephemeral_key, bob.spk_pub);
    assert_eq!(e.chains.len(), 1);
    assert!(e.get_chain(&ratchet.pub_key).is_some());
    let pending = e.pending_pre_key.as_ref().unwrap();
    assert_eq!(pending.base_key, base.pub_key);
    assert_eq!(pending.pre_key_id, Some(7));
    assert_eq!(pending.signed_pre_key_id, 3);

    let mut rb = SessionRecord::new();
    let out = encrypt(&mut ra, &a_pub, 11, b"x").unwrap();
    decrypt_prekey_message(&mut rb, &incoming(&bob, true), &out.body).unwrap();
    let eb = rb.sessions.values().next().unwrap();
    assert_eq!(
      eb.index_info.as_ref().unwrap().base_key_type,
      BASE_KEY_THEIRS
    );
    assert_eq!(eb.index_info.as_ref().unwrap().base_key, base.pub_key);
    assert!(eb.pending_pre_key.is_none());
  }

  #[test]
  fn second_bundle_closes_previous_open_session() {
    let (a_pub, a_priv) = identity(0x42);
    let alice = LocalIdentity {
      priv_key: &a_priv,
      pub_key: &a_pub,
    };
    let bob = bob();
    let mut ra = SessionRecord::new();
    process_prekey_bundle(&mut ra, &alice, &bundle(&bob, false)).unwrap();
    process_prekey_bundle(&mut ra, &alice, &bundle(&bob, false)).unwrap();
    assert_eq!(ra.sessions.len(), 2);
    assert_eq!(ra.sessions.values().filter(|s| !s.is_closed()).count(), 1);
  }

  #[test]
  fn old_closed_sessions_are_pruned() {
    let (a_pub, a_priv) = identity(0x42);
    let alice = LocalIdentity {
      priv_key: &a_priv,
      pub_key: &a_pub,
    };
    let bob = bob();
    let mut ra = SessionRecord::new();
    for _ in 0..60 {
      process_prekey_bundle(&mut ra, &alice, &bundle(&bob, false)).unwrap();
    }
    assert!(ra.sessions.len() <= crate::session_record::CLOSED_SESSIONS_MAX);
    assert!(ra.have_open_session());
  }

  #[test]
  fn invalid_inputs_are_rejected_without_touching_the_record() {
    let (a_pub, a_priv) = identity(0x42);
    let alice = LocalIdentity {
      priv_key: &a_priv,
      pub_key: &a_pub,
    };
    let bob = bob();

    let mut b = bundle(&bob, false);
    let mut sig = bob.spk_sig;
    sig[0] ^= 1;
    b.signed_pre_key_signature = &sig;
    let mut r = SessionRecord::new();
    assert!(matches!(
      process_prekey_bundle(&mut r, &alice, &b),
      Err(BuilderError::InvalidSignature)
    ));
    assert!(r.sessions.is_empty());

    let (other_pub, _) = identity(0x11);
    let wrong = LocalIdentity {
      priv_key: &a_priv,
      pub_key: &other_pub,
    };
    assert!(matches!(
      process_prekey_bundle(&mut r, &wrong, &bundle(&bob, false)),
      Err(BuilderError::IdentityMismatch)
    ));

    let mut b32 = bundle(&bob, false);
    b32.signed_pre_key = &bob.spk_pub[1..];
    assert!(matches!(
      process_prekey_bundle(&mut r, &alice, &b32),
      Err(BuilderError::InvalidKey(_))
    ));
    assert!(r.sessions.is_empty());
  }

  #[test]
  fn recipient_rejects_bad_keys_and_missing_prekey() {
    let (a_pub, a_priv) = identity(0x42);
    let alice = LocalIdentity {
      priv_key: &a_priv,
      pub_key: &a_pub,
    };
    let bob = bob();
    let mut ra = SessionRecord::new();
    process_prekey_bundle(&mut ra, &alice, &bundle(&bob, true)).unwrap();
    let out = encrypt(&mut ra, &a_pub, 11, b"x").unwrap();

    let mut rb = SessionRecord::new();
    assert!(matches!(
      decrypt_prekey_message(&mut rb, &incoming(&bob, false), &out.body),
      Err(BuilderError::InvalidPreKeyId)
    ));

    let (wrong_pub, _) = identity(0x12);
    let mut keys = incoming(&bob, true);
    keys.signed_pre_key = KeyPairRef {
      pub_key: &wrong_pub,
      priv_key: &bob.spk_priv,
    };
    let mut rb = SessionRecord::new();
    assert!(matches!(
      decrypt_prekey_message(&mut rb, &keys, &out.body),
      Err(BuilderError::SignedPreKeyMismatch)
    ));
  }
}
