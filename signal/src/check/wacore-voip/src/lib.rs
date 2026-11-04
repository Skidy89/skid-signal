//! The sans-IO WhatsApp call stack: call/group-call stanzas, the call control plane, relay parsing, STUN/WARP, SRTP and
//! SFrame, the MLow codec and the call engine. Vendored from wacore's `voip` and `voip_control` modules; owns no socket,
//! clock or thread.

extern crate self as wacore;

pub use wacore_binary as binary;
pub use wacore_derive::{EmptyNode, ProtocolNode, WireEnum};
pub use wacore_libsignal as libsignal;

pub mod crypto;
pub mod protocol;
pub mod runtime;
pub mod stanza {
  pub mod call;
  pub mod group_call;
}
pub mod stats;
pub mod sync_marker;
pub mod time;
pub mod types {
  pub mod call;
  pub mod group_call;
}
pub mod voip;
pub mod voip_control;
