use std::path::Path;

use cargo_metadata::Metadata;
use chrono::Local;

pub(crate) fn current_datetime() -> String {
    let now = Local::now();
    now.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Re-run the cargo command if the Cargo.toml or Cargo.lock file changes.
pub(crate) fn cargo_rerun_if_changed(metadata: &Metadata, program_dir: &Path) {
    // Tell cargo to rerun the script only if program/{src, bin, build.rs, Cargo.toml} changes
    // Ref: https://doc.rust-lang.org/nightly/cargo/reference/build-scripts.html#rerun-if-changed
    let dirs = vec![
        program_dir.join("src"),
        program_dir.join("bin"),
        program_dir.join("build.rs"),
        program_dir.join("Cargo.toml"),
    ];
    for dir in dirs {
        if dir.exists() {
            println!("cargo::rerun-if-changed={}", dir.canonicalize().unwrap().display());
        }
    }

    // Re-run the build script if the workspace root's Cargo.lock changes. If the program is its own
    // workspace, this will be the program's Cargo.lock.
    println!("cargo:rerun-if-changed={}", metadata.workspace_root.join("Cargo.lock").as_str());

    // Re-run if any local dependency changes.
    for package in &metadata.packages {
        for dependency in &package.dependencies {
            if let Some(path) = &dependency.path {
                println!("cargo:rerun-if-changed={}", path.as_str());
            }
        }
    }
}
