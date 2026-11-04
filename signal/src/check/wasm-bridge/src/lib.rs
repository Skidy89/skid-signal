// velowa (https://github.com/7ucg/velowa) (c) 2026 Baron. Copying any part of this file, however small, requires credit: see LICENSE.
//! Thin wasm-bindgen bridge over the vendored wacore-{binary,libsignal,noise,
//! appstate} crates. See `/prompt.md` (repo root) for the architecture this
//! crate is responsible for, and `/TODO.md` for the phased build-out — modules are added per phase (Phase 1: `binary`, Phase 2: `noise`, Phase 3: `signal`, Phase 4: `appstate`).
//!
//! Keep this crate thin: no protocol orchestration, no state held across
//! calls unless a wrapped crate's own API requires it. Orchestration stays
//! in src/Socket (ported from baron-baileys-v2), same as it is today.

pub mod appstate;
pub mod binary;
pub mod noise;
pub mod signal;

use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Phase-0 smoke test: proves the wasm32 build + wasm-bindgen export pipeline
/// works end to end before any real binding code is written. Delete once
/// Phase 1's real exports (WABinary encode/decode) exist.
#[wasm_bindgen]
pub fn velowa_bridge_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
