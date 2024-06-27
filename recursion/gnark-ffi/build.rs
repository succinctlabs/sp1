#![allow(unused)]

use cfg_if::cfg_if;
use std::env;
use std::path::PathBuf;
use std::process::Command;

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
            let dest = dest_path.join(format!("lib{}.a", lib_name));

            println!("Building Go library at {}", dest.display());

            // Run the go build command
            let status = Command::new("go")
                .current_dir("go")
                .env("CGO_ENABLED", "1")
                .args([
                    "build",
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
            let header_path = dest_path.join(format!("lib{}.h", lib_name));
            let bindings = bindgen::Builder::default()
                .header(header_path.to_str().unwrap())
                .parse_callbacks(Box::new(CargoCallbacks::new()))
                .generate()
                .expect("Unable to generate bindings");

            bindings
                .write_to_file(dest_path.join("bindings.rs"))
                .expect("Couldn't write bindings!");

            println!("Go library built");

            // Link the Go library
            println!("cargo:rustc-link-search=native={}", dest_path.display());
            println!("cargo:rustc-link-lib=static={}", lib_name);

	    println!("cargo:rustc-link-search=/home/kevin_succinct/go/pkg/mod/github.com/ingonyama-zk/icicle/v2@v2.0.0-20240620074550-c92881fb7d1c/icicle/build/lib");
            println!("cargo:rustc-link-lib=ingo_field_bn254");
            println!("cargo:rustc-link-lib=ingo_curve_bn254");

	    println!("cargo:rustc-link-search=/usr/local/cuda/lib64/");
	    println!("cargo:rustc-link-lib=cudart");

	    println!("cargo:rustc-link-lib=stdc++");

            // Static linking doesn't really work on macos, so we need to link some system libs
            if cfg!(target_os = "macos") {
                println!("cargo:rustc-link-lib=framework=CoreFoundation");
                println!("cargo:rustc-link-lib=framework=Security");
            }
        }
    }
}
