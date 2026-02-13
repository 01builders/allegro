//! Build script to generate Rust types from proto files using prost.

use std::path::PathBuf;

fn main() {
    let proto_dir = PathBuf::from("../../proto");
    let proto_files = [
        proto_dir.join("types.proto"),
        proto_dir.join("sidecar.proto"),
        proto_dir.join("aggregator.proto"),
    ];

    for file in &proto_files {
        println!("cargo:rerun-if-changed={}", file.display());
    }

    let mut config = prost_build::Config::new();
    config.compile_well_known_types();

    config
        .compile_protos(&proto_files, &[proto_dir])
        .expect("failed to compile FastPay protobuf definitions");
}
