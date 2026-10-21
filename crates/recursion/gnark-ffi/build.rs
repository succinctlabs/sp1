#![allow(unused)]

use cfg_if::cfg_if;
use std::{collections::HashMap, env, path::PathBuf, process::Command};

/// Build the go library, generate Rust bindings for the exposed functions, and link the library.
#[allow(clippy::uninlined_format_args)]
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

            if cfg!(feature = "plonk-cuda") {
                println!("cargo:rerun-if-changed=cuda");
                let cuda_home = cuda_home();
                let obj = dest_path.join("plonk.o");
                let status = Command::new(cuda_home.join("bin/nvcc"))
                    .args(["-O3", "-std=c++17", "-arch=all-major", "-Xcompiler", "-fPIC", "-c", "cuda/plonk.cu", "-o"])
                    .arg(&obj)
                    .status()
                    .expect("Failed to run nvcc");
                if !status.success() {
                    panic!("nvcc failed");
                }
                let status = Command::new("ar")
                    .arg("rcs")
                    .arg(dest_path.join("libsp1plonk.a"))
                    .arg(&obj)
                    .status()
                    .expect("Failed to run ar");
                if !status.success() {
                    panic!("ar failed");
                }
                println!("cargo:rustc-link-lib=static=sp1plonk");
                println!("cargo:rustc-link-search=native={}", cuda_home.join("lib64").display());
                println!("cargo:rustc-link-lib=dylib=cudart");
                println!("cargo:rustc-link-lib=dylib=stdc++");
            }

            if cfg!(feature = "groth16-cuda") || cfg!(feature = "plonk-cuda") {
                println!("cargo:rustc-link-search=native=/usr/local/lib");
                println!("cargo:rustc-link-lib=dylib=icicle_device");
                println!("cargo:rustc-link-lib=dylib=icicle_field_bn254");
                println!("cargo:rustc-link-lib=dylib=icicle_curve_bn254");
            }
            if cfg!(feature = "groth16-cuda") {
                println!("cargo:rustc-link-lib=dylib=icicle_field_bls12_377");
                println!("cargo:rustc-link-lib=dylib=icicle_curve_bls12_377");
                println!("cargo:rustc-link-lib=dylib=icicle_field_bls12_381");
                println!("cargo:rustc-link-lib=dylib=icicle_curve_bls12_381");
                println!("cargo:rustc-link-lib=dylib=icicle_field_bw6_761");
                println!("cargo:rustc-link-lib=dylib=icicle_curve_bw6_761");
                // Ideally we would also set the RPATH/RUNPATH using the following
                // println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/local/lib");
                // Unfortunately, this doesn't work. See:
                // https://github.com/rust-lang/cargo/pull/9557#issuecomment-884302305
            }

            let mut tags = vec!["debug"];
            if cfg!(feature = "groth16-cuda") {
                tags.push("icicle");
            }
            if cfg!(feature = "plonk-cuda") {
                tags.push("plonkcuda");
            }
            let tags = format!("-tags={}", tags.join(","));

            let mut go_envs = go_envs;
            if cfg!(feature = "plonk-cuda") {
                let flags = go_envs.entry("CGO_LDFLAGS".to_string()).or_default();
                *flags = format!(
                    "{flags} -L{} -L{} -L/usr/local/lib",
                    dest_path.display(),
                    cuda_home().join("lib64").display()
                );
            }
            let status = Command::new("go")
                .current_dir("go")
                .env("CGO_ENABLED", "1")
                .envs(go_envs)
                .args([
                    "build",
                    &tags,
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

            // Copy go/koalabear.h to OUT_DIR/koalabear.h
            let header_src = PathBuf::from("go/koalabear.h");
            let header_dest = dest_path.join("koalabear.h");
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

/// The CUDA toolkit root: `CUDA_HOME`, `CUDA_PATH`, or the parent of the `bin` holding `nvcc`.
fn cuda_home() -> PathBuf {
    if let Ok(home) = env::var("CUDA_HOME").or_else(|_| env::var("CUDA_PATH")) {
        return PathBuf::from(home);
    }
    env::var_os("PATH")
        .and_then(|paths| env::split_paths(&paths).find(|p| p.join("nvcc").exists()))
        .and_then(|bin| bin.parent().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/usr/local/cuda"))
}
