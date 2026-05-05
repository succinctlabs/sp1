// build.rs
// This script handles the building (or overriding) of the internal helper binary.
//
// MAIN LOGIC WRITTEN BY GEMINI 3

use cargo_metadata::MetadataCommand;
use sha2::{Digest, Sha256};
use std::env;
use std::process::Command;

// --- CONFIGURATION ---
// The name of the environment variable used to override the binary.
const OVERRIDE_ENV_VAR: &str = "SP1_CORE_RUNNER_OVERRIDE_BINARY";
// The package name of the inner binary crate (resolved via cargo metadata).
const INNER_CRATE_NAME: &str = "sp1-core-executor-runner-binary";

fn main() {
    // This is a quick-and-dirty fix so when sp1-core-executor or sp1-jit
    // changes, our runner also gets rebuild.
    println!("cargo:rerun-if-changed=../executor");
    println!("cargo:rerun-if-changed=../jit");

    sp1_core_executor::build::detect_executor();

    println!("cargo:rerun-if-env-changed={}", OVERRIDE_ENV_VAR);

    // =========================================================
    // PATH 1: OVERRIDE MODE
    // =========================================================
    // If the user provides a path via environment variable, we:
    // 1. Skip building the inner crate entirely.
    // 2. Do NOT embed any bytes (handled via cfg in lib.rs).
    // 3. Point the runtime code to the external file.
    if let Ok(override_path) = env::var(OVERRIDE_ENV_VAR) {
        // Resolve to absolute path to ensure runtime safety
        let abs_path = std::fs::canonicalize(&override_path).unwrap_or_else(|_| {
            panic!(
                "Override binary path defined in {} does not exist: {}",
                OVERRIDE_ENV_VAR, override_path
            )
        });

        println!("cargo:warning=Using external override binary: {}", abs_path.display());

        // Pass the path to the Rust code
        println!("cargo:rustc-env={}={}", OVERRIDE_ENV_VAR, abs_path.display());

        // Set a config flag so we can use #[cfg(sp1_core_runner_override)] to skip include_bytes!
        println!("cargo:rustc-cfg=sp1_core_runner_override");

        return; // EXIT EARLY - Do not build the inner crate!
    }

    // =========================================================
    // PATH 2: BUILD MODE (Standard)
    // =========================================================
    // Resolve the binary crate's manifest path via cargo metadata. This works both
    // in a workspace (path points to the workspace member) and when installed from
    // crates.io (path points to the registry cache).
    let metadata = MetadataCommand::new().exec().expect("Failed to run cargo metadata");

    let package = metadata
        .packages
        .iter()
        .find(|p| p.name == INNER_CRATE_NAME)
        .unwrap_or_else(|| panic!("Could not find {INNER_CRATE_NAME} in cargo metadata"));

    let inner_manifest_path = package.manifest_path.as_std_path();
    let inner_crate_path = inner_manifest_path.parent().unwrap();

    // 1. Watch the inner directory for changes
    println!("cargo:rerun-if-changed={}", inner_crate_path.display());

    // 2. Identify the target binary name from the package metadata.
    let bin_target = package
        .targets
        .iter()
        .find(|t| t.kind.iter().any(|k| k == "bin"))
        .unwrap_or_else(|| panic!("{INNER_CRATE_NAME} has no [[bin]] target!"));

    let binary_name = &bin_target.name;

    // 3. Build the inner crate
    let profile = env::var("PROFILE").unwrap();
    let mut cmd = Command::new("cargo");
    cmd.arg("build").arg("--manifest-path").arg(inner_manifest_path);

    // Pass the profile (release/debug)
    if profile == "release" {
        cmd.arg("--release");
    }

    #[cfg(feature = "profiling")]
    cmd.arg("--features").arg("profiling");

    #[cfg(feature = "mprotect")]
    cmd.arg("--features").arg("mprotect");

    let inner_target_dir = metadata.target_directory.join("sp1-native-bins");
    cmd.env("CARGO_TARGET_DIR", &inner_target_dir);

    // Clear inherited RUSTFLAGS to avoid cross-compilation issues. When the outer
    // build targets e.g. x86_64-unknown-linux-musl with +crt-static, those flags
    // leak into this nested cargo invocation which builds for the host. On GNU
    // targets, +crt-static makes proc-macro crate types unavailable, breaking
    // proc-macro dependencies like ark-ff-asm.
    cmd.env_remove("RUSTFLAGS");
    cmd.env_remove("CARGO_ENCODED_RUSTFLAGS");

    let status = cmd.status().expect("Failed to execute cargo build for internal binary");
    if !status.success() {
        panic!("Failed to build internal binary: {}", binary_name);
    }

    // 4. Locate the artifact
    // We use the metadata target directory to find where Cargo put the binary.
    // This correctly handles workspaces and custom target directories.
    let mut bin_path = inner_target_dir.join(&profile).join(binary_name);

    if cfg!(windows) {
        bin_path.set_extension("exe");
    }

    // 5. Export path for embedding
    println!("cargo:rustc-env=SP1_CORE_RUNNER_BINARY={}", bin_path);

    // 6. Calculates and passes binary hash
    let mut hasher = Sha256::new();
    hasher.update(std::fs::read(&bin_path).expect("read binary"));
    let result = hasher.finalize();
    let hash_string = hex::encode(result);
    println!("cargo:rustc-env=SP1_CORE_RUNNER_BINARY_HASH={}", hash_string);

    println!("cargo:warning=Built new runner binary.");
}
