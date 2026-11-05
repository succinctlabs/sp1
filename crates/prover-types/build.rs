use chrono::prelude::*;
use std::{env, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Add /usr/include if it exists
    let mut includes = vec!["proto/"];
    if Path::new("/usr/include").exists() {
        includes.push("/usr/include");
    }

    // Generate protobuf code to OUT_DIR (default behavior)
    tonic_prost_build::configure()
        .protoc_arg("--experimental_allow_proto3_optional")
        .type_attribute(".", "#[derive(serde::Serialize,serde::Deserialize)]")
        .compile_protos(&["proto/worker.proto", "proto/cluster.proto"], &includes)?;

    println!("cargo:rerun-if-env-changed=BUILD_GIT_SHA");

    let git_sha = match env::var("BUILD_GIT_SHA") {
        Ok(git_sha) => git_sha,
        Err(_) => "unknown".to_string(),
    };

    let pretty_time = Utc::now().format("%Y-%m-%dT%H:%M:%S");
    let version_string = format!("{} {}", git_sha, pretty_time);
    println!("cargo:rustc-env=BUILD_VERSION={}", version_string);
    Ok(())
}
