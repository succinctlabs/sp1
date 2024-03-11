fn main() {
    println!("cargo:rerun-if-changed=proto");
    let mut config = prost_build::Config::new();
    config
        .out_dir("src/proto")
        .type_attribute(".", "#[derive(serde::Serialize,serde::Deserialize)]")
        .service_generator(twirp_build::service_generator())
        .compile_protos(&["./service.proto"], &["."])
        .unwrap();
}
