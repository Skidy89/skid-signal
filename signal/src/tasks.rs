use super::*;
use napi::Task;
use zeroize::Zeroize;
use rayon::prelude::*;

fn rec_from(bytes: Option<&[u8]>) -> napi::Result<SessionRecord> {
  match bytes {
    Some(b) => SessionRecord::deserialize(b).map_err(js_err),
    None => Ok(SessionRecord::new()),
  }
}

fn group_rec_from(bytes: Option<&[u8]>) -> napi::Result<SenderKeyRecord> {
  match bytes {
    Some(b) => group::deserialize_record(b).map_err(js_err),
    None => Ok(SenderKeyRecord::default()),
  }
}

struct OwnedKp {
  pub_key: Vec<u8>,
  priv_key: Vec<u8>,
}

impl OwnedKp {
  fn new(k: &KeyPairIn) -> Self {
    Self {
      pub_key: k.pub_key.to_vec(),
      priv_key: k.priv_key.to_vec(),
    }
  }
}

impl Drop for OwnedKp {
  fn drop(&mut self) {
    self.priv_key.zeroize();
  }
}

pub struct PlainOut {
  plaintext: Vec<u8>,
  new_record: Vec<u8>,
}

impl PlainOut {
  fn into_js(self) -> DecryptResult {
    DecryptResult {
      plaintext: self.plaintext.into(),
      new_record: self.new_record.into(),
    }
  }
}


pub struct GenKeyPairsTask {
  count: usize,
}

impl Task for GenKeyPairsTask {
  type Output = Vec<(Vec<u8>, Vec<u8>)>;
  type JsValue = Vec<CreateKeyPair>;

  fn compute(&mut self) -> napi::Result<Self::Output> {
    Ok(
      curve::generate_key_pairs_int(self.count)
        .into_iter()
        .map(|(p, s)| (Vec::from(p), Vec::from(s)))
        .collect(),
    )
  }

  fn resolve(&mut self, _env: Env, out: Self::Output) -> napi::Result<Self::JsValue> {
    Ok(
      out
        .into_iter()
        .map(|(p, s)| CreateKeyPair {
          pub_key: p.into(),
          priv_key: s.into(),
        })
        .collect(),
    )
  }
}

#[napi(ts_return_type = "Promise<Array<CreateKeyPair>>")]
pub fn generate_key_pairs_async(
  count: u32,
  signal: Option<AbortSignal>,
) -> AsyncTask<GenKeyPairsTask> {
  AsyncTask::with_optional_signal(
    GenKeyPairsTask {
      count: count as usize,
    },
    signal,
  )
}


pub struct SessionEncryptTask {
  record: Vec<u8>,
  our_identity_pub: Vec<u8>,
  our_registration_id: u32,
  plaintext: Vec<u8>,
}

pub struct SessionEncryptOut {
  msg_type: u32,
  body: Vec<u8>,
  registration_id: u32,
  new_record: Vec<u8>,
}

impl Task for SessionEncryptTask {
  type Output = SessionEncryptOut;
  type JsValue = EncryptResult;

  fn compute(&mut self) -> napi::Result<Self::Output> {
    let mut rec = rec_from(Some(self.record.as_slice()))?;
    let out = session_cipher::encrypt(
      &mut rec,
      &self.our_identity_pub,
      self.our_registration_id,
      &self.plaintext,
    )
    .map_err(js_err)?;
    Ok(SessionEncryptOut {
      msg_type: u32::from(out.msg_type),
      body: out.body.into(),
      registration_id: out.registration_id,
      new_record: rec.serialize().into(),
    })
  }

  fn resolve(&mut self, _env: Env, o: Self::Output) -> napi::Result<Self::JsValue> {
    Ok(EncryptResult {
      msg_type: o.msg_type,
      body: o.body.into(),
      registration_id: o.registration_id,
      new_record: o.new_record.into(),
    })
  }
}

#[napi(ts_return_type = "Promise<EncryptResult>")]
pub fn session_encrypt_async(
  record: Buffer,
  our_identity_pub: Buffer,
  our_registration_id: u32,
  plaintext: Buffer,
) -> AsyncTask<SessionEncryptTask> {
  AsyncTask::new(SessionEncryptTask {
    record: record.to_vec(),
    our_identity_pub: our_identity_pub.to_vec(),
    our_registration_id,
    plaintext: plaintext.to_vec(),
  })
}


pub struct SessionDecryptWhisperTask {
  record: Vec<u8>,
  our_identity_pub: Vec<u8>,
  msg: Vec<u8>,
}

impl Task for SessionDecryptWhisperTask {
  type Output = PlainOut;
  type JsValue = DecryptResult;

  fn compute(&mut self) -> napi::Result<Self::Output> {
    let mut rec = rec_from(Some(self.record.as_slice()))?;
    let plaintext =
      session_cipher::decrypt_whisper_message_consume(&mut rec, &self.our_identity_pub, &self.msg)
        .map_err(js_err)?;
    Ok(PlainOut {
      plaintext: plaintext.into(),
      new_record: rec.serialize().into(),
    })
  }

  fn resolve(&mut self, _env: Env, o: Self::Output) -> napi::Result<Self::JsValue> {
    Ok(o.into_js())
  }
}

#[napi(ts_return_type = "Promise<DecryptResult>")]
pub fn session_decrypt_whisper_async(
  record: Buffer,
  our_identity_pub: Buffer,
  msg: Buffer,
) -> AsyncTask<SessionDecryptWhisperTask> {
  AsyncTask::new(SessionDecryptWhisperTask {
    record: record.to_vec(),
    our_identity_pub: our_identity_pub.to_vec(),
    msg: msg.to_vec(),
  })
}


pub struct ProcessBundleTask {
  record: Option<Vec<u8>>,
  our_identity: OwnedKp,
  registration_id: u32,
  identity_key: Vec<u8>,
  signed_pre_key_id: u32,
  signed_pre_key: Vec<u8>,
  signed_pre_key_signature: Vec<u8>,
  pre_key: Option<(u32, Vec<u8>)>,
}

impl Task for ProcessBundleTask {
  type Output = Vec<u8>;
  type JsValue = Buffer;

  fn compute(&mut self) -> napi::Result<Self::Output> {
    let mut rec = rec_from(self.record.as_deref())?;
    let remote = RemoteBundle {
      registration_id: self.registration_id,
      identity_key: &self.identity_key,
      signed_pre_key_id: self.signed_pre_key_id,
      signed_pre_key: &self.signed_pre_key,
      signed_pre_key_signature: &self.signed_pre_key_signature,
      pre_key: self.pre_key.as_ref().map(|(id, k)| (*id, k.as_slice())),
    };
    let ours = LocalIdentity {
      priv_key: &self.our_identity.priv_key,
      pub_key: &self.our_identity.pub_key,
    };
    x3dhra::process_prekey_bundle(&mut rec, &ours, &remote).map_err(js_err)?;
    Ok(rec.serialize().into())
  }

  fn resolve(&mut self, _env: Env, o: Self::Output) -> napi::Result<Self::JsValue> {
    Ok(o.into())
  }
}

#[napi(ts_return_type = "Promise<Buffer>")]
pub fn session_process_prekey_bundle_async(
  record: Option<Buffer>,
  our_identity: KeyPairIn,
  bundle: PreKeyBundleIn,
) -> napi::Result<AsyncTask<ProcessBundleTask>> {
  let pre_key = match (bundle.pre_key_id, bundle.pre_key.as_ref()) {
    (Some(id), Some(k)) => Some((id, k.to_vec())),
    (None, None) => None,
    _ => return Err(js_err("preKeyId and preKey must be provided together")),
  };
  Ok(AsyncTask::new(ProcessBundleTask {
    record: record.map(|b| b.to_vec()),
    our_identity: OwnedKp::new(&our_identity),
    registration_id: bundle.registration_id,
    identity_key: bundle.identity_key.to_vec(),
    signed_pre_key_id: bundle.signed_pre_key_id,
    signed_pre_key: bundle.signed_pre_key.to_vec(),
    signed_pre_key_signature: bundle.signed_pre_key_signature.to_vec(),
    pre_key,
  }))
}


pub struct SessionDecryptPreKeyTask {
  record: Option<Vec<u8>>,
  identity: OwnedKp,
  signed_pre_key: OwnedKp,
  pre_key: Option<OwnedKp>,
  msg: Vec<u8>,
}

pub struct PreKeyOut {
  plaintext: Vec<u8>,
  new_record: Vec<u8>,
  used_pre_key_id: Option<u32>,
}

impl Task for SessionDecryptPreKeyTask {
  type Output = PreKeyOut;
  type JsValue = PreKeyDecryptResult;

  fn compute(&mut self) -> napi::Result<Self::Output> {
    let mut rec = rec_from(self.record.as_deref())?;
    let keys = IncomingKeys {
      identity: LocalIdentity {
        priv_key: &self.identity.priv_key,
        pub_key: &self.identity.pub_key,
      },
      signed_pre_key: KeyPairRef {
        pub_key: &self.signed_pre_key.pub_key,
        priv_key: &self.signed_pre_key.priv_key,
      },
      pre_key: self.pre_key.as_ref().map(|k| KeyPairRef {
        pub_key: &k.pub_key,
        priv_key: &k.priv_key,
      }),
    };
    let out = x3dhra::decrypt_prekey_message(&mut rec, &keys, &self.msg).map_err(js_err)?;
    Ok(PreKeyOut {
      plaintext: out.plaintext.into(),
      new_record: rec.serialize().into(),
      used_pre_key_id: out.used_pre_key_id,
    })
  }

  fn resolve(&mut self, _env: Env, o: Self::Output) -> napi::Result<Self::JsValue> {
    Ok(PreKeyDecryptResult {
      plaintext: o.plaintext.into(),
      new_record: o.new_record.into(),
      used_pre_key_id: o.used_pre_key_id,
    })
  }
}

#[napi(ts_return_type = "Promise<PreKeyDecryptResult>")]
pub fn session_decrypt_prekey_async(
  record: Option<Buffer>,
  our_identity: KeyPairIn,
  signed_pre_key: KeyPairIn,
  pre_key: Option<KeyPairIn>,
  msg: Buffer,
) -> AsyncTask<SessionDecryptPreKeyTask> {
  AsyncTask::new(SessionDecryptPreKeyTask {
    record: record.map(|b| b.to_vec()),
    identity: OwnedKp::new(&our_identity),
    signed_pre_key: OwnedKp::new(&signed_pre_key),
    pre_key: pre_key.as_ref().map(OwnedKp::new),
    msg: msg.to_vec(),
  })
}


pub struct GroupCreateSkdmTask {
  record: Option<Vec<u8>>,
}

pub struct GroupSkdmOut {
  skdm: Vec<u8>,
  new_record: Vec<u8>,
}

impl Task for GroupCreateSkdmTask {
  type Output = GroupSkdmOut;
  type JsValue = GroupSkdmResult;

  fn compute(&mut self) -> napi::Result<Self::Output> {
    let mut rec = group_rec_from(self.record.as_deref())?;
    let skdm = group::create_distribution_message(&mut rec).map_err(js_err)?;
    Ok(GroupSkdmOut {
      skdm: skdm.into(),
      new_record: group::serialize_record(&rec).into(),
    })
  }

  fn resolve(&mut self, _env: Env, o: Self::Output) -> napi::Result<Self::JsValue> {
    Ok(GroupSkdmResult {
      skdm: o.skdm.into(),
      new_record: o.new_record.into(),
    })
  }
}

#[napi(ts_return_type = "Promise<GroupSkdmResult>")]
pub fn group_create_distribution_message_async(
  record: Option<Buffer>,
) -> AsyncTask<GroupCreateSkdmTask> {
  AsyncTask::new(GroupCreateSkdmTask {
    record: record.map(|b| b.to_vec()),
  })
}

pub struct GroupProcessSkdmTask {
  record: Option<Vec<u8>>,
  skdm: Vec<u8>,
}

impl Task for GroupProcessSkdmTask {
  type Output = Vec<u8>;
  type JsValue = Buffer;

  fn compute(&mut self) -> napi::Result<Self::Output> {
    let mut rec = group_rec_from(self.record.as_deref())?;
    group::process_distribution_message(&mut rec, &self.skdm).map_err(js_err)?;
    Ok(group::serialize_record(&rec).into())
  }

  fn resolve(&mut self, _env: Env, o: Self::Output) -> napi::Result<Self::JsValue> {
    Ok(o.into())
  }
}

#[napi(ts_return_type = "Promise<Buffer>")]
pub fn group_process_distribution_message_async(
  record: Option<Buffer>,
  skdm: Buffer,
) -> AsyncTask<GroupProcessSkdmTask> {
  AsyncTask::new(GroupProcessSkdmTask {
    record: record.map(|b| b.to_vec()),
    skdm: skdm.to_vec(),
  })
}


pub struct GroupEncryptTask {
  record: Vec<u8>,
  plaintext: Vec<u8>,
  legacy_iterations: bool,
}

pub struct GroupEncryptOut {
  ciphertext: Vec<u8>,
  new_record: Vec<u8>,
}

impl Task for GroupEncryptTask {
  type Output = GroupEncryptOut;
  type JsValue = GroupEncryptResult;

  fn compute(&mut self) -> napi::Result<Self::Output> {
    let mut rec = group_rec_from(Some(self.record.as_slice()))?;
    let ciphertext =
      group::encrypt(&mut rec, &self.plaintext, self.legacy_iterations).map_err(js_err)?;
    Ok(GroupEncryptOut {
      ciphertext: ciphertext.into(),
      new_record: group::serialize_record(&rec).into(),
    })
  }

  fn resolve(&mut self, _env: Env, o: Self::Output) -> napi::Result<Self::JsValue> {
    Ok(GroupEncryptResult {
      ciphertext: o.ciphertext.into(),
      new_record: o.new_record.into(),
    })
  }
}

#[napi(ts_return_type = "Promise<GroupEncryptResult>")]
pub fn group_encrypt_async(
  record: Buffer,
  plaintext: Buffer,
  legacy_iterations: Option<bool>,
) -> AsyncTask<GroupEncryptTask> {
  AsyncTask::new(GroupEncryptTask {
    record: record.to_vec(),
    plaintext: plaintext.to_vec(),
    legacy_iterations: legacy_iterations.unwrap_or(false),
  })
}


pub struct GroupEncryptSkdmTask {
  record: Option<Vec<u8>>,
  plaintext: Vec<u8>,
  legacy_iterations: bool,
}

pub struct GroupEncryptSkdmOut {
  ciphertext: Vec<u8>,
  skdm: Vec<u8>,
  new_record: Vec<u8>,
}

impl Task for GroupEncryptSkdmTask {
  type Output = GroupEncryptSkdmOut;
  type JsValue = GroupEncryptWithSkdmResult;

  fn compute(&mut self) -> napi::Result<Self::Output> {
    let mut rec = group_rec_from(self.record.as_deref())?;
    let (ciphertext, skdm) =
      group::encrypt_group_message(&mut rec, &self.plaintext, self.legacy_iterations)
        .map_err(js_err)?;
    Ok(GroupEncryptSkdmOut {
      ciphertext: ciphertext.into(),
      skdm: skdm.into(),
      new_record: group::serialize_record(&rec).into(),
    })
  }

  fn resolve(&mut self, _env: Env, o: Self::Output) -> napi::Result<Self::JsValue> {
    Ok(GroupEncryptWithSkdmResult {
      ciphertext: o.ciphertext.into(),
      skdm: o.skdm.into(),
      new_record: o.new_record.into(),
    })
  }
}

#[napi(ts_return_type = "Promise<GroupEncryptWithSkdmResult>")]
pub fn group_encrypt_with_skdm_async(
  record: Option<Buffer>,
  plaintext: Buffer,
  legacy_iterations: Option<bool>,
) -> AsyncTask<GroupEncryptSkdmTask> {
  AsyncTask::new(GroupEncryptSkdmTask {
    record: record.map(|b| b.to_vec()),
    plaintext: plaintext.to_vec(),
    legacy_iterations: legacy_iterations.unwrap_or(false),
  })
}


pub struct GroupDecryptTask {
  record: Option<Vec<u8>>,
  msg: Vec<u8>,
}

impl Task for GroupDecryptTask {
  type Output = PlainOut;
  type JsValue = DecryptResult;

  fn compute(&mut self) -> napi::Result<Self::Output> {
    let mut rec = group_rec_from(self.record.as_deref())?;
    let plaintext = group::decrypt(&mut rec, &self.msg).map_err(js_err)?;
    Ok(PlainOut {
      plaintext: plaintext.into(),
      new_record: group::serialize_record(&rec).into(),
    })
  }

  fn resolve(&mut self, _env: Env, o: Self::Output) -> napi::Result<Self::JsValue> {
    Ok(o.into_js())
  }
}

#[napi(ts_return_type = "Promise<DecryptResult>")]
pub fn group_decrypt_async(record: Option<Buffer>, msg: Buffer) -> AsyncTask<GroupDecryptTask> {
  AsyncTask::new(GroupDecryptTask {
    record: record.map(|b| b.to_vec()),
    msg: msg.to_vec(),
  })
}

#[napi(object)]
pub struct EncryptItemIn {
  pub record: Buffer,
  pub plaintext: Buffer,
}

#[napi(object)]
pub struct EncryptManyItem {
  pub msg_type: u32,
  pub body: Buffer,
  pub registration_id: u32,
  pub new_record: Buffer,
  pub error: Option<String>,
}

pub struct SessionEncryptManyTask {
  items: Vec<(Vec<u8>, Vec<u8>)>,
  our_identity_pub: Vec<u8>,
  our_registration_id: u32,
}

impl Task for SessionEncryptManyTask {
  type Output = Vec<std::result::Result<SessionEncryptOut, String>>;
  type JsValue = Vec<EncryptManyItem>;

  fn compute(&mut self) -> napi::Result<Self::Output> {
    let ident = &self.our_identity_pub;
    let reg = self.our_registration_id;
    Ok(
      self
        .items
        .par_iter()
        .map(|(record, plaintext)| -> std::result::Result<SessionEncryptOut, String> {
          let mut rec = SessionRecord::deserialize(record).map_err(|e| e.to_string())?;
          let out = session_cipher::encrypt(&mut rec, ident, reg, plaintext).map_err(|e| e.to_string())?;
          Ok(SessionEncryptOut {
            msg_type: u32::from(out.msg_type),
            body: out.body.into(),
            registration_id: out.registration_id,
            new_record: rec.serialize().into(),
          })
        })
        .collect(),
    )
  }

  fn resolve(&mut self, _env: Env, outs: Self::Output) -> napi::Result<Self::JsValue> {
    Ok(
      outs
        .into_iter()
        .map(|r| match r {
          Ok(o) => EncryptManyItem {
            msg_type: o.msg_type,
            body: o.body.into(),
            registration_id: o.registration_id,
            new_record: o.new_record.into(),
            error: None,
          },
          Err(e) => EncryptManyItem {
            msg_type: 0,
            body: Vec::new().into(),
            registration_id: 0,
            new_record: Vec::new().into(),
            error: Some(e),
          },
        })
        .collect(),
    )
  }
}

#[napi(ts_return_type = "Promise<Array<EncryptManyItem>>")]
pub fn session_encrypt_many_async(
  items: Vec<EncryptItemIn>,
  our_identity_pub: Buffer,
  our_registration_id: u32,
) -> AsyncTask<SessionEncryptManyTask> {
  AsyncTask::new(SessionEncryptManyTask {
    items: items.iter().map(|i| (i.record.to_vec(), i.plaintext.to_vec())).collect(),
    our_identity_pub: our_identity_pub.to_vec(),
    our_registration_id,
  })
}