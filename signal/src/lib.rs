pub mod crypto;
pub mod curve;
pub mod group;
pub mod session_cipher;
pub mod session_record;
pub mod utils;
pub mod wire;
pub mod x3dhra;
use crate::curve::{generate_key_pair_int, shared_secret_int, sign, verify};
use crate::group::SenderKeyRecord;
use crate::session_record::SessionRecordExt;
use crate::utils::scrub_pub_key;
use crate::x3dhra::{extract, IncomingKeys, KeyPairRef, LocalIdentity, RemoteBundle};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use signal_proto::signal::session::SessionRecord;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
const KEY_TYPE: u8 = 0x05;

fn js_err<E: std::fmt::Display>(e: E) -> napi::Error {
  napi::Error::from_reason(e.to_string())
}

fn record_from(record: Option<Buffer>) -> napi::Result<SessionRecord> {
  match record {
    Some(b) => SessionRecord::deserialize(&b).map_err(js_err),
    None => Ok(SessionRecord::new()),
  }
}
#[inline]
fn pub32(b: &[u8]) -> napi::Result<[u8; 32]> {
  let raw = match b.len() {
    33 if b[0] == KEY_TYPE => &b[1..],
    32 => b,
    _ => return Err(js_err("Invalid public key")),
  };
  Ok(raw.try_into().unwrap())
}
#[inline]
fn clamp(k: &mut [u8; 32]) {
  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;
}

#[inline]
fn priv32(b: &[u8]) -> napi::Result<[u8; 32]> {
  b.try_into().map_err(|_| js_err("Invalid private key"))
}
fn pack(sk: &[u8; 32]) -> Buffer {
  let mut out = vec![0u8; 65];
  out[..32].copy_from_slice(sk);
  out[32] = KEY_TYPE;
  out[33..].copy_from_slice(&x25519(*sk, X25519_BASEPOINT_BYTES));
  out.into()
}
#[napi(object)]
pub struct CreateKeyPair {
  pub pub_key: Buffer,
  pub priv_key: Buffer,
}

#[napi(object)]
pub struct KeyPairIn {
  pub pub_key: Buffer,
  pub priv_key: Buffer,
}

#[napi(object)]
pub struct PreKeyBundleIn {
  pub registration_id: u32,
  pub identity_key: Buffer,
  pub signed_pre_key_id: u32,
  pub signed_pre_key: Buffer,
  pub signed_pre_key_signature: Buffer,
  pub pre_key_id: Option<u32>,
  pub pre_key: Option<Buffer>,
}

#[napi(object)]
pub struct ParsedPreKeyMessage {
  pub registration_id: u32,
  pub pre_key_id: Option<u32>,
  pub signed_pre_key_id: u32,
  pub base_key: Buffer,
  pub identity_key: Buffer,
}

#[napi(object)]
pub struct EncryptResult {
  /// 1 = WhisperMessage, 3 = PreKeyWhisperMessage
  pub msg_type: u32,
  pub body: Buffer,
  pub registration_id: u32,
  pub new_record: Buffer,
}

#[napi(object)]
pub struct DecryptResult {
  pub plaintext: Buffer,
  pub new_record: Buffer,
}

#[napi(object)]
pub struct PreKeyDecryptResult {
  pub plaintext: Buffer,
  pub new_record: Buffer,
  pub used_pre_key_id: Option<u32>,
}

#[napi]
pub fn session_have_open(record: Buffer) -> napi::Result<bool> {
  Ok(
    SessionRecord::deserialize(&record)
      .map_err(js_err)?
      .have_open_session(),
  )
}

#[napi]
pub fn session_encrypt(
  record: Buffer,
  our_identity_pub: Buffer,
  our_registration_id: u32,
  plaintext: Buffer,
) -> napi::Result<EncryptResult> {
  let mut rec = SessionRecord::deserialize(&record).map_err(js_err)?;
  let out = session_cipher::encrypt(&mut rec, &our_identity_pub, our_registration_id, &plaintext)
    .map_err(js_err)?;
  Ok(EncryptResult {
    msg_type: u32::from(out.msg_type),
    body: out.body.into(),
    registration_id: out.registration_id,
    new_record: rec.serialize().into(),
  })
}

#[napi]
pub fn session_decrypt_whisper(
  record: Buffer,
  our_identity_pub: Buffer,
  msg: Buffer,
) -> napi::Result<DecryptResult> {
  let mut rec = SessionRecord::deserialize(&record).map_err(js_err)?;
  let plaintext =
    session_cipher::decrypt_whisper_message_consume(&mut rec, &our_identity_pub, &msg)
      .map_err(js_err)?;
  Ok(DecryptResult {
    plaintext: plaintext.into(),
    new_record: rec.serialize().into(),
  })
}
#[napi]
pub fn generate_key_pairs(count: u32) -> napi::Result<Vec<CreateKeyPair>> {
  let pairs = curve::generate_key_pairs_int(count as usize);
  let result = pairs
    .into_iter()
    .map(|(pub_key, priv_key)| CreateKeyPair {
      pub_key: Buffer::from(Vec::from(pub_key)),
      priv_key: Buffer::from(Vec::from(priv_key)),
    })
    .collect();
  Ok(result)
}
#[napi]
pub fn session_process_prekey_bundle(
  record: Option<Buffer>,
  our_identity: KeyPairIn,
  bundle: PreKeyBundleIn,
) -> napi::Result<Buffer> {
  let mut rec = record_from(record)?;
  let pre_key = match (bundle.pre_key_id, bundle.pre_key.as_ref()) {
    (Some(id), Some(k)) => Some((id, &k[..])),
    (None, None) => None,
    _ => return Err(js_err("preKeyId and preKey must be provided together")),
  };
  let remote = RemoteBundle {
    registration_id: bundle.registration_id,
    identity_key: &bundle.identity_key,
    signed_pre_key_id: bundle.signed_pre_key_id,
    signed_pre_key: &bundle.signed_pre_key,
    signed_pre_key_signature: &bundle.signed_pre_key_signature,
    pre_key,
  };
  let ours = LocalIdentity {
    priv_key: &our_identity.priv_key,
    pub_key: &our_identity.pub_key,
  };
  x3dhra::process_prekey_bundle(&mut rec, &ours, &remote).map_err(js_err)?;
  Ok(rec.serialize().into())
}

#[napi]
pub fn parse_prekey_message(msg: Buffer) -> napi::Result<ParsedPreKeyMessage> {
  let m = wire::decode_prekey_whisper(&msg).map_err(js_err)?;
  let missing = |what: &str| js_err(format!("Malformed PreKeyWhisperMessage: missing {what}"));
  Ok(ParsedPreKeyMessage {
    registration_id: m.registration_id.unwrap_or(0),
    pre_key_id: m.pre_key_id,
    signed_pre_key_id: m
      .signed_pre_key_id
      .ok_or_else(|| missing("signedPreKeyId"))?,
    base_key: m.base_key.ok_or_else(|| missing("baseKey"))?.into(),
    identity_key: m.identity_key.ok_or_else(|| missing("identityKey"))?.into(),
  })
}

#[napi]
pub fn session_decrypt_prekey(
  record: Option<Buffer>,
  our_identity: KeyPairIn,
  signed_pre_key: KeyPairIn,
  pre_key: Option<KeyPairIn>,
  msg: Buffer,
) -> napi::Result<PreKeyDecryptResult> {
  let mut rec = record_from(record)?;
  let keys = IncomingKeys {
    identity: LocalIdentity {
      priv_key: &our_identity.priv_key,
      pub_key: &our_identity.pub_key,
    },
    signed_pre_key: KeyPairRef {
      pub_key: &signed_pre_key.pub_key,
      priv_key: &signed_pre_key.priv_key,
    },
    pre_key: pre_key.as_ref().map(|k| KeyPairRef {
      pub_key: &k.pub_key,
      priv_key: &k.priv_key,
    }),
  };
  let out = x3dhra::decrypt_prekey_message(&mut rec, &keys, &msg).map_err(js_err)?;
  Ok(PreKeyDecryptResult {
    plaintext: out.plaintext.into(),
    new_record: rec.serialize().into(),
    used_pre_key_id: out.used_pre_key_id,
  })
}

fn group_record_from(record: Option<Buffer>) -> napi::Result<SenderKeyRecord> {
  match record {
    Some(b) => group::deserialize_record(&b).map_err(js_err),
    None => Ok(SenderKeyRecord::default()),
  }
}

#[napi(object)]
pub struct GroupSkdmResult {
  pub skdm: Buffer,
  pub new_record: Buffer,
}

#[napi(object)]
pub struct GroupEncryptResult {
  pub ciphertext: Buffer,
  pub new_record: Buffer,
}

#[napi(object)]
pub struct GroupEncryptWithSkdmResult {
  pub ciphertext: Buffer,
  pub skdm: Buffer,
  pub new_record: Buffer,
}

#[napi]
pub fn group_create_distribution_message(record: Option<Buffer>) -> napi::Result<GroupSkdmResult> {
  let mut rec = group_record_from(record)?;
  let skdm = group::create_distribution_message(&mut rec).map_err(js_err)?;
  Ok(GroupSkdmResult {
    skdm: skdm.into(),
    new_record: group::serialize_record(&rec).into(),
  })
}

#[napi]
pub fn group_process_distribution_message(
  record: Option<Buffer>,
  skdm: Buffer,
) -> napi::Result<Buffer> {
  let mut rec = group_record_from(record)?;
  group::process_distribution_message(&mut rec, &skdm).map_err(js_err)?;
  Ok(group::serialize_record(&rec).into())
}

#[napi]
pub fn group_encrypt(
  record: Buffer,
  plaintext: Buffer,
  legacy_iterations: Option<bool>,
) -> napi::Result<GroupEncryptResult> {
  let mut rec = group::deserialize_record(&record).map_err(js_err)?;
  let ciphertext =
    group::encrypt(&mut rec, &plaintext, legacy_iterations.unwrap_or(false)).map_err(js_err)?;
  Ok(GroupEncryptResult {
    ciphertext: ciphertext.into(),
    new_record: group::serialize_record(&rec).into(),
  })
}

#[napi]
pub fn group_encrypt_with_skdm(
  record: Option<Buffer>,
  plaintext: Buffer,
  legacy_iterations: Option<bool>,
) -> napi::Result<GroupEncryptWithSkdmResult> {
  let mut rec = group_record_from(record)?;
  let (ciphertext, skdm) =
    group::encrypt_group_message(&mut rec, &plaintext, legacy_iterations.unwrap_or(false))
      .map_err(js_err)?;
  Ok(GroupEncryptWithSkdmResult {
    ciphertext: ciphertext.into(),
    skdm: skdm.into(),
    new_record: group::serialize_record(&rec).into(),
  })
}

#[napi]
pub fn group_decrypt(record: Option<Buffer>, msg: Buffer) -> napi::Result<DecryptResult> {
  let mut rec = group_record_from(record)?;
  let plaintext = group::decrypt(&mut rec, &msg).map_err(js_err)?;
  Ok(DecryptResult {
    plaintext: plaintext.into(),
    new_record: group::serialize_record(&rec).into(),
  })
}

#[napi]
pub fn verify_signature(sig: Buffer, pub_key: Buffer, message: Buffer) -> napi::Result<bool> {
  let sig_array: &[u8; 64] = sig.as_ref().try_into().map_err(js_err)?;

  Ok(
    verify(pub_key.as_ref(), message.as_ref(), sig_array)
      .map_err(js_err)
      .unwrap(),
  )
}

#[napi]
pub fn generate_key_pair() -> napi::Result<CreateKeyPair> {
  let (pub_key, priv_key) = generate_key_pair_int();

  let result = CreateKeyPair {
    pub_key: Buffer::from(Vec::from(pub_key)),
    priv_key: Buffer::from(Vec::from(priv_key)),
  };
  Ok(result)
}

#[napi]
pub fn shared_secret(pub_key: Buffer, priv_key: Buffer) -> napi::Result<Buffer> {
  let pub_key_scrubbed = scrub_pub_key(&pub_key).unwrap();
  if priv_key.len() != 32 {
    return Err(js_err("Private key must be 32 bytes"));
  }
  let priv_key_array: [u8; 32] = priv_key.as_ref().try_into().map_err(js_err)?;
  let shared = shared_secret_int(pub_key_scrubbed.as_ref(), priv_key_array).map_err(js_err)?;

  Ok(Buffer::from(Vec::from(shared)))
}

#[napi]
pub fn sign_message(priv_key: Buffer, message: Buffer) -> napi::Result<Buffer> {
  if priv_key.len() != 32 {
    return Err(js_err("Private key must be 32 bytes"));
  }
  let priv_key_array: &[u8] = priv_key.as_ref().try_into().map_err(js_err)?;
  let sig = sign(priv_key_array, message.as_ref(), None).map_err(js_err)?;

  Ok(Buffer::from(Vec::from(sig)))
}

#[napi]
pub fn calculate_agreement(pub_key: Buffer, priv_key: Buffer) -> napi::Result<Buffer> {
  let pk: [u8; 32] = pub_key.as_ref()[pub_key.len() - 32..]
    .try_into()
    .map_err(js_err)?;
  let sk: [u8; 32] = priv_key.as_ref().try_into().map_err(js_err)?;
  Ok(x25519(sk, pk).to_vec().into())
}

#[napi]
pub fn x25519_agree(pub_key: Buffer, priv_key: Buffer) -> napi::Result<Buffer> {
  let shared = x25519(priv32(&priv_key)?, pub32(&pub_key)?);
  if shared.iter().all(|&b| b == 0) {
    return Err(js_err("Invalid public key"));
  }
  Ok(Buffer::from(shared.to_vec()))
}

#[napi]
pub fn x25519_generate_key_pair() -> napi::Result<Buffer> {
  let mut sk = [0u8; 32];
  getrandom::getrandom(&mut sk).map_err(|e| js_err(e.to_string()))?;
  clamp(&mut sk);
  Ok(pack(&sk))
}

#[napi]
pub fn x25519_create_key_pair(priv_key: Uint8Array) -> napi::Result<Buffer> {
  let mut sk = priv32(&priv_key)?;
  clamp(&mut sk);
  Ok(pack(&sk))
}

#[napi]
pub fn x25519_public_from_private(priv_key: Uint8Array) -> Result<Buffer> {
  let sk = priv32(&priv_key)?;
  let mut out = [0u8; 33];
  out[0] = KEY_TYPE;
  out[1..].copy_from_slice(&x25519(sk, X25519_BASEPOINT_BYTES));
  Ok(Buffer::from(out.to_vec()))
}

#[napi]
pub fn extract_identity_from_pkmsg(ciphertext: Uint8Array) -> Option<Buffer> {
  extract(&ciphertext).map(|k| Buffer::from(k.to_vec()))
}
