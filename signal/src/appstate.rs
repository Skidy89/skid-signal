use napi::bindgen_prelude::*;
use napi_derive::napi;
use wacore_appstate::hash::{generate_content_mac, generate_index_mac};
use wacore_appstate::keys::expand_app_state_keys;
use wacore_appstate::lthash::WAPATCH_INTEGRITY;
use waproto::whatsapp as wa;

fn js_err(error: impl std::fmt::Display) -> napi::Error {
  napi::Error::from_reason(error.to_string())
}

#[napi(object)]
pub struct ExpandedAppStateKeys {
  pub index: Buffer,
  pub value_encryption: Buffer,
  pub value_mac: Buffer,
  pub snapshot_mac: Buffer,
  pub patch_mac: Buffer,
}

#[napi]
pub fn app_state_expand_keys(master_key: Buffer) -> napi::Result<ExpandedAppStateKeys> {
  if master_key.len() != 32 {
    return Err(js_err("masterKey must be 32 bytes"));
  }
  let keys = expand_app_state_keys(&master_key);
  Ok(ExpandedAppStateKeys {
    index: Buffer::from(keys.index.to_vec()),
    value_encryption: Buffer::from(keys.value_encryption.to_vec()),
    value_mac: Buffer::from(keys.value_mac.to_vec()),
    snapshot_mac: Buffer::from(keys.snapshot_mac.to_vec()),
    patch_mac: Buffer::from(keys.patch_mac.to_vec()),
  })
}

#[napi]
pub fn app_state_lthash(
  base: Buffer,
  subtract: Vec<Buffer>,
  add: Vec<Buffer>,
) -> napi::Result<Buffer> {
  if base.len() != 128 || subtract.iter().any(|item| item.len() != 128) || add.iter().any(|item| item.len() != 128) {
    return Err(js_err("LTHash inputs must all be 128 bytes"));
  }
  let mut output = base.to_vec();
  WAPATCH_INTEGRITY.subtract_then_add_in_place(&mut output, &subtract, &add);
  Ok(Buffer::from(output))
}

#[napi]
pub fn app_state_index_mac(index: Buffer, key: Buffer) -> napi::Result<Buffer> {
  let key: [u8; 32] = key
    .as_ref()
    .try_into()
    .map_err(|_| js_err("index MAC key must be 32 bytes"))?;
  Ok(Buffer::from(generate_index_mac(&index, &key)))
}

#[napi]
pub fn app_state_content_mac(
  operation: u32,
  data: Buffer,
  key_id: Buffer,
  key: Buffer,
) -> napi::Result<Buffer> {
  let operation = match operation {
    0 => wa::syncd_mutation::SyncdOperation::SET,
    1 => wa::syncd_mutation::SyncdOperation::REMOVE,
    _ => return Err(js_err("operation must be 0 (SET) or 1 (REMOVE)")),
  };
  if key.is_empty() {
    return Err(js_err("content MAC key must not be empty"));
  }
  Ok(Buffer::from(
    generate_content_mac(operation, &data, &key_id, &key).to_vec(),
  ))
}
