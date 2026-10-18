use std::io::Result;

fn main() -> Result<()> {
    let mut config = prost_build::Config::new();
    config.btree_map(["."]);

    config.compile_protos(
        &[
            "src/proto/wire.proto",
            "src/proto/session.proto",
            "src/proto/group_wire.proto",
        ],
        &["src/"],
    )?;

    println!("cargo:rerun-if-changed=src/proto/wire.proto");
    println!("cargo:rerun-if-changed=src/proto/session.proto");
    println!("cargo:rerun-if-changed=src/proto/group_wire.proto");

    Ok(())
}