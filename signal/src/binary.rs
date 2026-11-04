use napi::bindgen_prelude::*;
use napi_derive::napi;
use wacore_binary::jid::parse_jid_fast;
use wacore_binary::{marshal_auto, Node, NodeRef};

fn js_err(error: impl std::fmt::Display) -> napi::Error {
  napi::Error::from_reason(error.to_string())
}

#[napi(object)]
pub struct ParsedJid {
  pub user: String,
  pub server: String,
  pub agent: u8,
  pub device: u16,
  pub integrator: u16,
}

#[napi]
pub fn binary_pack(node_bytes: Buffer) -> Buffer {
  Buffer::from(wacore_binary::util::pack(&node_bytes))
}

#[napi]
pub fn binary_unpack(data: Buffer) -> napi::Result<Buffer> {
  wacore_binary::util::unpack(&data)
    .map(|bytes| Buffer::from(bytes.into_owned()))
    .map_err(js_err)
}

#[napi]
pub fn binary_marshal_node(node_json: String) -> napi::Result<Buffer> {
  let node: Node = serde_json::from_str(&node_json).map_err(js_err)?;
  marshal_auto(&node).map(Buffer::from).map_err(js_err)
}

#[napi]
pub fn binary_unmarshal_node(data: Buffer) -> napi::Result<String> {
  let node: NodeRef<'_> = wacore_binary::marshal::unmarshal_ref(&data).map_err(js_err)?;
  serde_json::to_string(&node).map_err(js_err)
}

#[napi]
pub fn binary_marshal_packed_node(node_json: String) -> napi::Result<Buffer> {
  let node: Node = serde_json::from_str(&node_json).map_err(js_err)?;
  wacore_binary::marshal::marshal(&node)
    .map(Buffer::from)
    .map_err(js_err)
}

#[napi]
pub fn binary_unmarshal_packed_node(data: Buffer) -> napi::Result<String> {
  let node = wacore_binary::marshal::unmarshal_packed_ref(&data).map_err(js_err)?;
  serde_json::to_string(&node).map_err(js_err)
}

#[napi]
pub fn parse_jid(value: String) -> napi::Result<ParsedJid> {
  let parts = parse_jid_fast(&value).ok_or_else(|| js_err("Invalid JID"))?;
  Ok(ParsedJid {
    user: parts.user.to_owned(),
    server: parts.server.to_owned(),
    agent: parts.agent,
    device: parts.device,
    integrator: parts.integrator,
  })
}

#[napi]
pub fn jid_to_string(value: String) -> napi::Result<String> {
  value
    .parse::<wacore_binary::Jid>()
    .map(|jid| jid.to_string())
    .map_err(js_err)
}

#[napi]
pub fn jid_to_compact(value: String) -> napi::Result<String> {
  value
    .parse::<wacore_binary::Jid>()
    .map(|jid| jid.to_string())
    .map_err(js_err)
}
