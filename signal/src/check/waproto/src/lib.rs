//! Auto-generated protobuf definitions for the WhatsApp wire format.
//!
//! The Rust source (`whatsapp.rs`) is produced by `build.rs` from the
//! pre-compiled descriptor set `whatsapp.desc`, and written to `OUT_DIR` —
//! not tracked in git. To regenerate the descriptor after editing
//! `whatsapp.proto`, run `cargo xt proto-desc` (wraps `protoc`).

#![allow(clippy::large_enum_variant)]
/// Re-exported because its types permeate the generated API; depending on it
/// directly would require version-matching this crate exactly.
pub use buffa;

pub mod whatsapp {
  // disallowed_methods: the generated impls call the buffa trait methods on
  // nested messages; that IS the pinned instantiation.
  // unused_qualifications: the generator emits fully-qualified paths on
  // purpose so the output cannot collide with names in the including scope.
  #![allow(
    non_camel_case_types,
    non_snake_case,
    unreachable_patterns,
    unused_qualifications,
    clippy::derivable_impls,
    clippy::match_single_binding,
    clippy::needless_else,
    clippy::disallowed_methods
  )]
  #[rustfmt::skip]
    buffa::include_proto!("whatsapp");
}

/// Field-level serde for `Option<EnumValue<E>>` fields (open enums, currently
/// only `SyncdMutation.operation`), wired in via `field_attribute` in
/// `build.rs`.
///
/// `EnumValue`'s own serde impls speak exact protobuf names (`SET`) on both
/// sides, which would silently break the per-feature contracts the closed
/// enums honor: `serde-enum-repr` serializes numerically for the JS bridge,
/// and `serde-snake-case` deserializes lowercase variant names. Routing the
/// known-value case through the enum's derived impls keeps an opened field on
/// exactly the closed-enum contract; only `Unknown` values add behavior
/// (serialized as, and deserializable from, the raw integer).
pub mod open_enum_serde {
  use buffa::{EnumValue, Enumeration};

  pub fn serialize<E, S>(value: &Option<EnumValue<E>>, s: S) -> Result<S::Ok, S::Error>
  where
    E: Enumeration + serde::Serialize,
    S: serde::Serializer,
  {
    match value {
      None => s.serialize_none(),
      Some(EnumValue::Known(e)) => s.serialize_some(e),
      Some(EnumValue::Unknown(n)) => s.serialize_some(n),
    }
  }

  #[cfg(feature = "serde-deserialize")]
  pub fn deserialize<'de, E, D>(d: D) -> Result<Option<EnumValue<E>>, D::Error>
  where
    E: Enumeration + serde::Deserialize<'de>,
    D: serde::Deserializer<'de>,
  {
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum Wire<E> {
      // The enum's derived impl first, so every feature-selected input
      // shape (lowercase names, numeric repr) keeps working; the raw
      // integer fallback only catches values the enum doesn't know.
      Known(E),
      Raw(i32),
    }
    Ok(
      match <Option<Wire<E>> as serde::Deserialize>::deserialize(d)? {
        None => None,
        Some(Wire::Known(e)) => Some(EnumValue::Known(e)),
        Some(Wire::Raw(n)) => Some(EnumValue::from(n)),
      },
    )
  }
}

/// Wire tags of every message field in `whatsapp.proto`, generated alongside
/// the buffa code. Hand-written partial decoders must reference these consts
/// (or compile-time assert against them) instead of magic numbers, so schema
/// changes surface as compile errors rather than silent wire-format drift.
pub mod tags {
  include!(concat!(env!("OUT_DIR"), "/tags.rs"));
}

/// Pinned, non-generic codec entry points for the hottest protobuf roots.
///
/// buffa's `Message` encode/decode methods are generic over the buffer type, so
/// rustc instantiates them in every crate that calls them; the per-crate copies
/// carry distinct instantiating-crate symbol hashes that LTO cannot merge, and
/// each calling crate ends up shipping its own copy of the full encode/decode
/// tree. Routing calls through these functions pins a single instantiation in
/// this crate; `#[inline(never)]` keeps MIR inlining from re-expanding them at
/// call sites, which would silently reintroduce the per-crate copies.
///
/// Decode helpers take `&[u8]` and decode via `decode_from_slice`, the buffer
/// shape the rest of the workspace already instantiates, so no second
/// buffer-type tree exists.
// The pinning wrappers are the one sanctioned direct-call site (see
// clippy.toml disallowed-methods).
#[allow(clippy::disallowed_methods)]
pub mod codec {
  use crate::whatsapp;

  use buffa::Message as _;

  /// Protobuf packs the field number above the 3-bit wire type in the tag.
  const PROTOBUF_WIRE_TYPE_BITS: u32 = 3;

  /// `SyncActionData` field numbers, read off `whatsapp.proto`.
  const SYNC_ACTION_DATA_INDEX: u32 = 1;

  const SYNC_ACTION_DATA_VALUE: u32 = 2;

  const SYNC_ACTION_DATA_PADDING: u32 = 3;

  const SYNC_ACTION_DATA_VERSION: u32 = 4;

  #[inline]
  fn push_varint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
      out.push((v as u8) | 0x80);
      v >>= 7;
    }
    out.push(v as u8);
  }

  #[inline]
  fn wire_tag_value(field: u32, wire_type: buffa::encoding::WireType) -> u64 {
    (u64::from(field) << PROTOBUF_WIRE_TYPE_BITS) | wire_type as u64
  }

  #[inline]
  fn push_wire_tag(field: u32, wire_type: buffa::encoding::WireType, out: &mut Vec<u8>) {
    push_varint(wire_tag_value(field, wire_type), out);
  }

  /// Bytes a base-128 varint occupies.
  #[inline]
  fn varint_len(mut v: u64) -> usize {
    let mut n = 1;
    while v >= 0x80 {
      v >>= 7;
      n += 1;
    }
    n
  }

  /// Encoded size of the length-delimited field `field` carrying `payload_len`
  /// bytes (key + length varint + payload), so a nested field's length can be
  /// pre-computed without a temp buffer.
  #[inline]
  fn len_delimited_len(field: u32, payload_len: usize) -> usize {
    varint_len(wire_tag_value(
      field,
      buffa::encoding::WireType::LengthDelimited,
    )) + varint_len(payload_len as u64)
      + payload_len
  }

  #[inline(never)]
  pub fn syncd_patch_decode(bytes: &[u8]) -> Result<whatsapp::SyncdPatch, buffa::DecodeError> {
    whatsapp::SyncdPatch::decode_from_slice(bytes)
  }

  #[inline(never)]
  pub fn syncd_patch_to_vec(patch: &whatsapp::SyncdPatch) -> Vec<u8> {
    patch.encode_to_vec()
  }

  #[inline(never)]
  pub fn syncd_snapshot_decode(
    bytes: &[u8],
  ) -> Result<whatsapp::SyncdSnapshot, buffa::DecodeError> {
    whatsapp::SyncdSnapshot::decode_from_slice(bytes)
  }

  #[inline(never)]
  pub fn sync_action_value_decode(
    bytes: &[u8],
  ) -> Result<whatsapp::SyncActionValue, buffa::DecodeError> {
    whatsapp::SyncActionValue::decode_from_slice(bytes)
  }

  #[inline(never)]
  pub fn sync_action_value_to_vec(value: &whatsapp::SyncActionValue) -> Vec<u8> {
    value.encode_to_vec()
  }

  #[inline(never)]
  pub fn external_blob_reference_decode(
    bytes: &[u8],
  ) -> Result<whatsapp::ExternalBlobReference, buffa::DecodeError> {
    whatsapp::ExternalBlobReference::decode_from_slice(bytes)
  }

  #[inline(never)]
  pub fn sync_action_data_decode(
    bytes: &[u8],
  ) -> Result<whatsapp::SyncActionData, buffa::DecodeError> {
    whatsapp::SyncActionData::decode_from_slice(bytes)
  }

  /// Encode a `SyncActionData` wrapping a borrowed action value, returning the
  /// wire bytes in one exactly-sized allocation.
  ///
  /// The app-state encode path holds the value behind a reference and fills the
  /// other three fields from scalars, so building an owned `SyncActionData`
  /// first deep-cloned the whole `SyncActionValue` subtree once per outgoing
  /// mutation purely to hand it to the generated encoder. Writing the four
  /// fields directly keeps that clone, the index copy and the empty padding
  /// vector out of the path. Field numbers are `SyncActionData`'s (index = 1,
  /// value = 2, padding = 3, version = 4); the app-state encode/decode
  /// roundtrip test is what holds them to the schema.
  ///
  /// `padding` is written as the empty byte string the previous owned form
  /// produced, so the bytes are identical to `SyncActionData::encode_to_vec`.
  #[inline(never)]
  pub fn sync_action_data_to_vec(
    index: &[u8],
    value: &whatsapp::SyncActionValue,
    version: i32,
  ) -> Vec<u8> {
    use buffa::encoding::WireType;

    // Size the value once; the same cache feeds `write_to` below.
    let mut cache = buffa::SizeCache::new();
    let value_len = value.compute_size(&mut cache) as usize;

    let total = len_delimited_len(SYNC_ACTION_DATA_INDEX, index.len())
      + len_delimited_len(SYNC_ACTION_DATA_VALUE, value_len)
      + len_delimited_len(SYNC_ACTION_DATA_PADDING, 0)
      + varint_len(wire_tag_value(SYNC_ACTION_DATA_VERSION, WireType::Varint))
      + buffa::types::int32_encoded_len(version);
    let mut out = Vec::with_capacity(total);

    push_wire_tag(SYNC_ACTION_DATA_INDEX, WireType::LengthDelimited, &mut out);
    push_varint(index.len() as u64, &mut out);
    out.extend_from_slice(index);

    push_wire_tag(SYNC_ACTION_DATA_VALUE, WireType::LengthDelimited, &mut out);
    push_varint(value_len as u64, &mut out);
    value.write_to(&mut cache, &mut out);

    push_wire_tag(
      SYNC_ACTION_DATA_PADDING,
      WireType::LengthDelimited,
      &mut out,
    );
    push_varint(0, &mut out);

    push_wire_tag(SYNC_ACTION_DATA_VERSION, WireType::Varint, &mut out);
    buffa::types::encode_int32(version, &mut out);

    debug_assert_eq!(out.len(), total, "two-pass size mismatch");
    out
  }

  /// Signal storage records. Decoded/encoded from wacore-libsignal and the
  /// prekey upload paths in the main crate — two private copies of each tree
  /// before being pinned here.
  #[inline(never)]
  pub fn pre_key_record_decode(
    bytes: &[u8],
  ) -> Result<whatsapp::PreKeyRecordStructure, buffa::DecodeError> {
    whatsapp::PreKeyRecordStructure::decode_from_slice(bytes)
  }

  #[inline(never)]
  pub fn pre_key_record_to_vec(record: &whatsapp::PreKeyRecordStructure) -> Vec<u8> {
    record.encode_to_vec()
  }

  #[inline(never)]
  pub fn signed_pre_key_record_decode(
    bytes: &[u8],
  ) -> Result<whatsapp::SignedPreKeyRecordStructure, buffa::DecodeError> {
    whatsapp::SignedPreKeyRecordStructure::decode_from_slice(bytes)
  }

  #[inline(never)]
  pub fn signed_pre_key_record_to_vec(record: &whatsapp::SignedPreKeyRecordStructure) -> Vec<u8> {
    record.encode_to_vec()
  }

  #[inline(never)]
  pub fn sender_key_record_decode(
    bytes: &[u8],
  ) -> Result<whatsapp::SenderKeyRecordStructure, buffa::DecodeError> {
    whatsapp::SenderKeyRecordStructure::decode_from_slice(bytes)
  }

  #[inline(never)]
  pub fn sender_key_record_to_vec(record: &whatsapp::SenderKeyRecordStructure) -> Vec<u8> {
    record.encode_to_vec()
  }

  #[inline(never)]
  pub fn handshake_message_decode(
    bytes: &[u8],
  ) -> Result<whatsapp::HandshakeMessage, buffa::DecodeError> {
    whatsapp::HandshakeMessage::decode_from_slice(bytes)
  }

  #[inline(never)]
  pub fn handshake_message_to_vec(msg: &whatsapp::HandshakeMessage) -> Vec<u8> {
    msg.encode_to_vec()
  }

  /// Noise server cert chain, verified once per connection in wacore-noise.
  #[inline(never)]
  pub fn cert_chain_decode(bytes: &[u8]) -> Result<whatsapp::CertChain, buffa::DecodeError> {
    whatsapp::CertChain::decode_from_slice(bytes)
  }

  #[inline(never)]
  pub fn noise_certificate_details_decode(
    bytes: &[u8],
  ) -> Result<whatsapp::cert_chain::noise_certificate::Details, buffa::DecodeError> {
    whatsapp::cert_chain::noise_certificate::Details::decode_from_slice(bytes)
  }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
  use super::whatsapp as wa;
  use buffa::Message as _;

  /// Wire-compat smoke test on the retained schema: encode, decode, compare.
  #[test]
  fn retained_types_round_trip() {
    let msg = wa::SignalMessage {
      ratchet_key: Some(vec![5; 33]),
      counter: Some(7),
      previous_counter: Some(3),
      ciphertext: Some(vec![1, 2, 3]),
    };
    let bytes = msg.encode_to_vec();
    let back = wa::SignalMessage::decode_from_slice(&bytes).unwrap();
    assert_eq!(back.counter, Some(7));
    assert_eq!(back.ciphertext.as_deref(), Some(&[1u8, 2, 3][..]));
  }
}
