use std::{env, path::Path, process::Command};

pub fn build() {
    let native = Path::new(env!("CARGO_MANIFEST_DIR")).join("native");
    let target = std::path::PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("native-target");
    println!("cargo:rerun-if-changed={}", native.display());

    // Separate executables keep each crate's own secp256k1-sys library.
    for suffix in ["029", "030"] {
        for kind in ["original", "patched"] {
            let name = format!("secp-native-{kind}-{suffix}");
            let manifest = native.join(format!("{kind}-{suffix}")).join("Cargo.toml");
            assert!(
                Command::new(env::var_os("CARGO").unwrap())
                    .args(["build", "--release", "--locked", "--jobs", "2", "--manifest-path"])
                    .arg(&manifest)
                    .arg("--target-dir")
                    .arg(&target)
                    .status()
                    .unwrap()
                    .success(),
                "failed to build {name}"
            );
            println!(
                "cargo:rustc-env=SECP_{}_{suffix}={}",
                kind.to_uppercase(),
                target.join("release").join(name).display()
            );
        }
    }
}
