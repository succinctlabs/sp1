fn main() {
    // This is commented out because it requires for the protobuf-compiler to be installed.
    //
    // println!("cargo:rerun-if-changed=.");
    // let mut config = prost_build::Config::new();
    // config
    //     .protoc_arg("--experimental_allow_proto3_optional")
    //     .out_dir("src/proto")
    //     .type_attribute(".", "#[derive(serde::Serialize,serde::Deserialize)]")
    //     .service_generator(twirp_build::service_generator())
    //     .compile_protos(&["proto/api.proto"], &["proto"])
    //     .unwrap();
}
