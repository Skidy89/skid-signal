// velowa (https://github.com/7ucg/velowa) (c) 2026 Baron. Copying any part of this file, however small, requires credit: see LICENSE.
//! WABinary codec exports.
//!
//! The node model crosses the boundary as plain JS data, not as opaque handles:
//!
//! ```ts
//! interface BinaryNode {
//!   tag: string
//!   attrs: Record<string, string>
//!   content?: string | Uint8Array | BinaryNode[]
//! }
//! ```
//!
//! Why data and not a wasm class: a node is a value that TS code reads, builds
//! and pattern-matches on constantly; a handle would force a boundary call per
//! field access. The codec itself is stateless, so `encodeNode`/`decodeNode`
//! are honest free functions (see docs/architecture.md, "Rust binding").
//!
//! JIDs: the decoder renders JID attributes as their string form and the
//! encoder re-detects JID-shaped strings, so a JID attribute round-trips to the
//! same bytes without a separate JID type on the wire boundary.
//!
//! Attribute order is carried by JS object key order. Attribute names are
//! never integer-like, so engines keep insertion order.

use js_sys::{Array, Object, Reflect, Uint8Array};
use wacore_binary::marshal::{marshal, unmarshal_ref};
use wacore_binary::node::{NodeContentRef, ValueRef};
use wacore_binary::util::unpack;
use wacore_binary::{Attrs, Node, NodeContent, NodeRef};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const TS_NODE: &str = r#"
/** A WABinary node. `content` may be a string, raw bytes or child nodes when encoding; a decoded node has only `Uint8Array` or `BinaryNode[]` (the wire format does not tell string from bytes). */
export interface BinaryNode {
  tag: string;
  attrs: Record<string, string>;
  content?: string | Uint8Array | BinaryNode[];
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "BinaryNode")]
    pub type JsBinaryNode;
}

fn err(msg: impl std::fmt::Display) -> JsError {
    JsError::new(&msg.to_string())
}

/// Encode a node to a frame payload: format byte (plain) + node bytes.
#[wasm_bindgen(js_name = encodeNode)]
pub fn encode_node(node: JsBinaryNode) -> Result<Vec<u8>, JsError> {
    let node = node_from_js(&node.into())?;
    marshal(&node).map_err(err)
}

/// Decode a frame payload (format byte + node bytes, zlib-compressed or not).
#[wasm_bindgen(js_name = decodeNode)]
pub fn decode_node(data: &[u8]) -> Result<JsBinaryNode, JsError> {
    let bytes = unpack(data).map_err(err)?;
    let node = unmarshal_ref(&bytes).map_err(err)?;
    Ok(node_to_js(&node)?.unchecked_into())
}

fn get(obj: &JsValue, key: &str) -> Result<JsValue, JsError> {
    Reflect::get(obj, &JsValue::from_str(key)).map_err(|_| err(format!("cannot read '{key}'")))
}

fn node_from_js(v: &JsValue) -> Result<Node, JsError> {
    let tag = get(v, "tag")?
        .as_string()
        .ok_or_else(|| err("node.tag must be a string"))?;

    let attrs_obj = get(v, "attrs")?;
    let mut attrs = Attrs::new();
    if !attrs_obj.is_undefined() && !attrs_obj.is_null() {
        for entry in Object::entries(attrs_obj.unchecked_ref()).iter() {
            let pair: Array = entry.unchecked_into();
            let key = pair.get(0).as_string().unwrap_or_default();
            let val = pair
                .get(1)
                .as_string()
                .ok_or_else(|| err(format!("attr '{key}' must be a string")))?;
            attrs.push(key, val);
        }
    }

    let c = get(v, "content")?;
    let content = if c.is_undefined() || c.is_null() {
        None
    } else if let Some(s) = c.as_string() {
        Some(NodeContent::String(s.into()))
    } else if c.is_instance_of::<Uint8Array>() {
        Some(NodeContent::Bytes(Uint8Array::from(c).to_vec()))
    } else if Array::is_array(&c) {
        let children = Array::from(&c)
            .iter()
            .map(|child| node_from_js(&child))
            .collect::<Result<Vec<_>, _>>()?;
        Some(NodeContent::Nodes(children))
    } else {
        return Err(err(
            "node.content must be string | Uint8Array | BinaryNode[]",
        ));
    };

    Ok(Node::new(tag, attrs, content))
}

fn node_to_js(node: &NodeRef<'_>) -> Result<JsValue, JsError> {
    let out = Object::new();
    let set = |o: &Object, k: &str, v: &JsValue| {
        Reflect::set(o, &JsValue::from_str(k), v)
            .map(|_| ())
            .map_err(|_| err(format!("cannot set '{k}'")))
    };

    set(&out, "tag", &JsValue::from_str(&node.tag))?;

    let attrs = Object::new();
    for (k, v) in node.attrs_iter() {
        let s = match v {
            ValueRef::String(s) => JsValue::from_str(s),
            ValueRef::Jid(j) => JsValue::from_str(&j.to_string()),
        };
        set(&attrs, k, &s)?;
    }
    set(&out, "attrs", &attrs)?;

    match &node.content {
        None => {}
        Some(NodeContentRef::String(s)) => set(&out, "content", &JsValue::from_str(s))?,
        Some(NodeContentRef::Bytes(b)) => set(&out, "content", &Uint8Array::from(&b[..]))?,
        Some(NodeContentRef::Nodes(children)) => {
            let arr = Array::new_with_length(children.len() as u32);
            for (i, c) in children.iter().enumerate() {
                arr.set(i as u32, node_to_js(c)?);
            }
            set(&out, "content", &arr)?;
        }
    }
    Ok(out.into())
}
