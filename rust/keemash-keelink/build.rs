// SPDX-License-Identifier: GPL-2.0-only

fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");
    std::env::set_var("PROTOC", protoc);
    prost_build::Config::new()
        .compile_protos(
            &["../../protocol/keelink-fabric-v2.proto"],
            &["../../protocol"],
        )
        .expect("compile KeeLink Fabric v2 schema");
    println!("cargo:rerun-if-changed=../../protocol/keelink-fabric-v2.proto");
}
