//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

fn main() {
    let protos = ["src/proto/provisioning.proto"];
    // protox compiles the schemas in-process, so the build does not need a protoc binary.
    let file_descriptors = protox::compile(protos, ["src"]).expect("Protobufs in src are valid");
    prost_build::Config::new()
        .compile_fds(file_descriptors)
        .expect("Protobufs in src are valid");
    for proto in &protos {
        println!("cargo:rerun-if-changed={proto}");
    }
}
