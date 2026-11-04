//! Generates the buffa types for the MLow constant tables from the committed descriptor
//! `src/voip/mlow/tables.desc` (compiled once from `tables.proto`), so no `protoc` is needed.

fn main() -> Result<(), Box<dyn std::error::Error>> {
  println!("cargo:rerun-if-changed=src/voip/mlow/tables.desc");
  println!("cargo:rerun-if-changed=build.rs");
  if std::env::var_os("CARGO_FEATURE_VOIP_MLOW").is_none() {
    return Ok(());
  }
  let out_dir = std::env::var("OUT_DIR")?;
  buffa_build::Config::new()
    .descriptor_set("src/voip/mlow/tables.desc")
    .files(&["tables.proto"])
    .preserve_unknown_fields(false)
    .out_dir(&out_dir)
    .compile()
}
