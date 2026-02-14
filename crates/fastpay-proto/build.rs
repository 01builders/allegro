//! Build script to generate Rust types and gRPC service stubs from proto files.

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

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&proto_files, &[proto_dir])
        .expect("failed to compile FastPay protobuf definitions");
}
