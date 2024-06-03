#![allow(unused)]

use cfg_if::cfg_if;
use std::env;
use std::path::PathBuf;
use std::process::Command;

#[allow(deprecated)]
use bindgen::CargoCallbacks;

/// Build the Docker image containing the GNARK bindings CLI application.
fn main() {
    cfg_if! {
        if #[cfg(feature = "plonk")] {
            println!("cargo:rerun-if-changed=go");
            println!("cargo:rerun-if-changed=gnark-cli");

            println!("Building Docker image");

            // Run the go build command
            let status = Command::new("docker")
                .args([
                    "build",
                    "-t",
                    "gnark-cli",
                    ".",
                ])
                .status()
                .expect("Failed to build Docker image");

            if !status.success() {
                panic!("Docker image build failed");
            }
        }
    }
}
