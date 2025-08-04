#![allow(unused)]

use cfg_if::cfg_if;
use std::{env, path::PathBuf, process::Command, collections::HashMap};

#[allow(deprecated)]
use bindgen::CargoCallbacks;

/// Build the go library, generate Rust bindings for the exposed functions, and link the library.
fn main() {
    cfg_if! {
        if #[cfg(feature = "native")] {
            println!("cargo:rerun-if-changed=go");
            // Define the output directory
            let out_dir = env::var("OUT_DIR").unwrap();
            let dest_path = PathBuf::from(&out_dir);
            let lib_name = "sp1gnark";
            let dest = dest_path.join(format!("lib{lib_name}.a"));

            // Parse custom environment for the `go build` command, e.g. to support cross-compilation.
            // The variable may contain a semi-colon-separated list of name=value pairs.
            // Example: SP1_GNARK_FFI_GO_ENVS="CC=clang-cl;CCC_OVERRIDE_OPTIONS=x-dM"
            let go_envs: HashMap<String, String> = match env::var("SP1_GNARK_FFI_GO_ENVS") {
                Ok(env_str) => env_str.split(';')
                    .map(|s| match s.split_once('=') {
                        Some((k, v)) => (k.to_string(), v.to_string()),
                        // A degenerate edge-case of a variable name w/o a value:
                        None => (s.to_string(), "".to_string()),
                    })
                    .collect(),
                Err(_) => HashMap::new(),
            };

            println!("Building Go library at {}", dest.display());

            // Run the go build command
            let status = Command::new("go")
                .current_dir("go")
                .env("CGO_ENABLED", "1")
                .envs(go_envs)
                .args([
                    "build",
                    "-tags=debug",
                    "-o",
                    dest.to_str().unwrap(),
                    "-buildmode=c-archive",
                    ".",
                ])
                .status()
                .expect("Failed to build Go library");
            if !status.success() {
                panic!("Go build failed");
            }

            // Copy go/babybear.h to OUT_DIR/babybear.h
            let header_src = PathBuf::from("go/babybear.h");
            let header_dest = dest_path.join("babybear.h");
            std::fs::copy(header_src, header_dest).unwrap();

            // Generate bindings using bindgen
            let header_path = dest_path.join(format!("lib{lib_name}.h"));
            let bindings = bindgen::Builder::default()
                .header(header_path.to_str().unwrap())
                .generate()
                .expect("Unable to generate bindings");

            bindings
                .write_to_file(dest_path.join("bindings.rs"))
                .expect("Couldn't write bindings!");

            println!("Go library built");

            // Link the Go library
            println!("cargo:rustc-link-search=native={}", dest_path.display());
            println!("cargo:rustc-link-lib=static={lib_name}");

            // Static linking doesn't really work on macos, so we need to link some system libs
            if cfg!(target_os = "macos") {
                // unless, of course, we're cross-building for another platform,
                // then we can use an env var to skip this:
                if env::var("SP1_GNARK_FFI_SKIP_MAC_FRAMEWORKS").is_err() {
                    println!("cargo:rustc-link-lib=framework=CoreFoundation");
                    println!("cargo:rustc-link-lib=framework=Security");
                }
            }
        }
    }
}
