# Vendored from oxidezap/whatsapp-rust

Source: https://github.com/oxidezap/whatsapp-rust, commit `0d1373a8f06e0dfa72f3ea1c4c33abae9fd21d61` (2026-10-31).

Copied from `wacore/src/`: `voip/`, `voip_control/`, `stanza/call.rs`, `stanza/group_call.rs`, `types/call.rs`,
`types/group_call.rs`, plus the small support modules they use (`runtime.rs`, `stats.rs`, `sync_marker.rs`, `time.rs`,
`crypto.rs`, `protocol/`; `protocol/retry.rs` dropped, two lines in `stats.rs` that called into the client crate removed).
The MLow tables build script is `build.rs` (descriptor `src/voip/mlow/tables.desc`).
