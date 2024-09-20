use std::{fs, path::Path};

use anyhow::Result;
use cargo_metadata::{camino::Utf8PathBuf, Metadata};
use chrono::Local;

use crate::{BuildArgs, BUILD_TARGET, HELPER_TARGET_SUBDIR};

/// Copy the ELF to the specified output directory.
pub(crate) fn copy_elf_to_output_dir(
    args: &BuildArgs,
    program_metadata: &cargo_metadata::Metadata,
) -> Result<Utf8PathBuf> {
    let root_package = program_metadata.root_package();
    let root_package_name = root_package.as_ref().map(|p| &p.name);

    // The ELF is written to a target folder specified by the program's package. If built with
    // Docker, includes /docker after HELPER_TARGET_SUBDIR.
    let target_dir_suffix = if args.docker {
        format!("{}/{}", HELPER_TARGET_SUBDIR, "docker")
    } else {
        HELPER_TARGET_SUBDIR.to_string()
    };

    // The ELF's file name is the binary name if it's specified. Otherwise, it is the root package
    // name.
    let original_elf_file_name = if !args.binary.is_empty() {
        args.binary.clone()
    } else {
        root_package_name.unwrap().clone()
    };

    let original_elf_path = program_metadata
        .target_directory
        .join(target_dir_suffix)
        .join(BUILD_TARGET)
        .join("release")
        .join(original_elf_file_name);

    // The order of precedence for the ELF name is:
    // 1. --elf_name flag
    // 2. --binary flag + -elf suffix (defaults to riscv32im-succinct-zkvm-elf)
    let elf_name = if !args.elf_name.is_empty() {
        args.elf_name.clone()
    } else if !args.binary.is_empty() {
        // TODO: In the future, change this to default to the package name. Will require updating
        // docs and examples.
        args.binary.clone()
    } else {
        BUILD_TARGET.to_string()
    };

    let elf_dir = program_metadata.target_directory.parent().unwrap().join(&args.output_directory);
    fs::create_dir_all(&elf_dir)?;
    let result_elf_path = elf_dir.join(elf_name);

    // Copy the ELF to the specified output directory.
    fs::copy(original_elf_path, &result_elf_path)?;

    Ok(result_elf_path)
}

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
