use std::{
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use cargo_metadata::camino::Utf8PathBuf;

use crate::{
    command::{docker::create_docker_command, local::create_local_command, utils::execute_command},
    utils::{cargo_rerun_if_changed, current_datetime},
    BuildArgs, BUILD_TARGET, HELPER_TARGET_SUBDIR,
};

/// Build a program with the specified [`BuildArgs`]. The `program_dir` is specified as an argument
/// when the program is built via `build_program`.
///
/// # Arguments
///
/// * `args` - A reference to a `BuildArgs` struct that holds various arguments used for building
///   the program.
/// * `program_dir` - An optional `PathBuf` specifying the directory of the program to be built.
///
/// # Returns
///
/// * `Result<Vec<(String, Utf8PathBuf)>>` - A list of mapping from bin target names to the paths to
///   the built program as a `Utf8PathBuf` on success, or an error on failure.
pub fn execute_build_program(
    args: &BuildArgs,
    program_dir: Option<PathBuf>,
) -> Result<Vec<(String, Utf8PathBuf)>> {
    // If the program directory is not specified, use the current directory.
    let program_dir = program_dir
        .unwrap_or_else(|| std::env::current_dir().expect("Failed to get current directory."));
    let program_dir: Utf8PathBuf =
        program_dir.try_into().expect("Failed to convert PathBuf to Utf8PathBuf");

    // Get the program metadata.
    let program_metadata_file = program_dir.join("Cargo.toml");
    let mut program_metadata_cmd = cargo_metadata::MetadataCommand::new();
    let program_metadata = program_metadata_cmd.manifest_path(program_metadata_file).exec()?;

    // Get the command corresponding to Docker or local build.
    let cmd = if args.docker {
        create_docker_command(args, &program_dir, &program_metadata)?
    } else {
        create_local_command(args, &program_dir, &program_metadata)
    };

    execute_command(cmd, args.docker)?;

    let target_elf_paths = generate_elf_paths(&program_metadata, Some(args))?;

    print_elf_paths_cargo_directives(&target_elf_paths);

    Ok(target_elf_paths)
}

/// Internal helper function to build the program with or without arguments.
///
/// Note: This function is not intended to be used by the CLI, as it looks for the sp1-sdk,
/// which is probably in the same crate lockfile as this function is only called by build scipr
pub(crate) fn build_program_internal(path: &str, args: Option<BuildArgs>) {
    // Get the root package name and metadata.
    let program_dir = std::path::Path::new(path);
    verify_locked_version(program_dir).expect("locked version mismatch");

    let metadata_file = program_dir.join("Cargo.toml");
    let mut metadata_cmd = cargo_metadata::MetadataCommand::new();
    let metadata = metadata_cmd.manifest_path(metadata_file).exec().unwrap();
    let root_package = metadata.root_package();
    let root_package_name = root_package.as_ref().map(|p| p.name.as_str()).unwrap_or("Program");

    // Skip the program build if the SP1_SKIP_PROGRAM_BUILD environment variable is set to true.
    let skip_program_build = std::env::var("SP1_SKIP_PROGRAM_BUILD")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if skip_program_build {
        // Still need to set ELF env vars even if build is skipped.
        let target_elf_paths = generate_elf_paths(&metadata, args.as_ref())
            .expect("failed to collect target ELF paths");

        print_elf_paths_cargo_directives(&target_elf_paths);

        println!(
            "cargo:warning=Build skipped for {} at {} due to SP1_SKIP_PROGRAM_BUILD flag",
            root_package_name,
            current_datetime()
        );
        return;
    }

    // Activate the build command if the dependencies change.
    cargo_rerun_if_changed(&metadata, program_dir);

    // Check if RUSTC_WORKSPACE_WRAPPER is set to clippy-driver (i.e. if `cargo clippy` is the
    // current compiler). If so, don't execute `cargo prove build` because it breaks
    // rust-analyzer's `cargo clippy` feature.
    let is_clippy_driver = std::env::var("RUSTC_WORKSPACE_WRAPPER")
        .map(|val| val.contains("clippy-driver"))
        .unwrap_or(false);
    if is_clippy_driver {
        // Still need to set ELF env vars even if build is skipped.
        let target_elf_paths = generate_elf_paths(&metadata, args.as_ref())
            .expect("failed to collect target ELF paths");

        print_elf_paths_cargo_directives(&target_elf_paths);

        println!("cargo:warning=Skipping build due to clippy invocation.");
        return;
    }

    // Build the program with the given arguments.
    let path_output = if let Some(args) = args {
        execute_build_program(&args, Some(program_dir.to_path_buf()))
    } else {
        execute_build_program(&BuildArgs::default(), Some(program_dir.to_path_buf()))
    };
    if let Err(err) = path_output {
        panic!("Failed to build SP1 program: {}.", err);
    }

    println!("cargo:warning={} built at {}", root_package_name, current_datetime());
}

/// Collects the list of targets that would be built and their output ELF file paths.
pub fn generate_elf_paths(
    metadata: &cargo_metadata::Metadata,
    args: Option<&BuildArgs>,
) -> Result<Vec<(String, Utf8PathBuf)>> {
    let mut target_elf_paths = vec![];
    let packages_to_iterate = if let Some(args) = args {
        if !args.packages.is_empty() {
            args.packages
                .iter()
                .map(|wanted_package| {
                    metadata
                        .packages
                        .iter()
                        .find(|p| p.name == *wanted_package)
                        .ok_or_else(|| {
                            anyhow::anyhow!("cannot find package named {}", wanted_package)
                        })
                        .map(|p| p.id.clone())
                })
                .collect::<anyhow::Result<Vec<_>>>()?
        } else {
            metadata.workspace_default_members.to_vec()
        }
    } else {
        metadata.workspace_default_members.to_vec()
    };

    for program_crate in packages_to_iterate {
        let program = metadata
            .packages
            .iter()
            .find(|p| p.id == program_crate)
            .ok_or_else(|| anyhow::anyhow!("cannot find package for {}", program_crate))?;

        for bin_target in program.targets.iter().filter(|t| {
            t.kind.contains(&"bin".to_owned()) && t.crate_types.contains(&"bin".to_owned())
        }) {
            // Filter out irrelevant targets if `--bin` is used.
            if let Some(args) = args {
                if !args.binaries.is_empty() && !args.binaries.contains(&bin_target.name) {
                    continue;
                }
            }

            let elf_path = metadata.target_directory.join(HELPER_TARGET_SUBDIR);
            let elf_path = match args {
                Some(args) if args.docker => elf_path.join("docker"),
                _ => elf_path,
            };
            let elf_path = elf_path.join(BUILD_TARGET).join("release").join(&bin_target.name);

            target_elf_paths.push((bin_target.name.to_owned(), elf_path));
        }
    }

    Ok(target_elf_paths)
}

/// Prints cargo directives setting relevant `SP1_ELF_` environment variables.
fn print_elf_paths_cargo_directives(target_elf_paths: &[(String, Utf8PathBuf)]) {
    for (target_name, elf_path) in target_elf_paths.iter() {
        println!("cargo:rustc-env=SP1_ELF_{}={}", target_name, elf_path);
    }
}

/// Verify that the locked version of `sp1-zkvm` in the Cargo.lock file is compatible with the
/// current version of this crate.
///
/// This also checks to ensure that `sp1-sdk` is also the correct version.
///
/// ## Note: This function assumes that version compatibility is given by matching major and minor
/// semver.
///
/// This is also correct if future releases sharing the workspace version, which should be the case.
fn verify_locked_version(program_dir: impl AsRef<Path>) -> Result<()> {
    #[derive(serde::Deserialize)]
    struct LockFile {
        package: Vec<Package>,
    }

    #[derive(serde::Deserialize)]
    struct Package {
        name: String,
        version: String,
    }

    // This might be a workspace, so we need optionally search parent dirs for lock files
    let canon = program_dir.as_ref().canonicalize()?;
    let mut lock_path = canon.join("Cargo.lock");
    if !lock_path.is_file() {
        let mut curr_path: &Path = canon.as_ref();

        while let Some(parent) = curr_path.parent() {
            let maybe_lock_path = parent.join("Cargo.lock");

            if maybe_lock_path.is_file() {
                lock_path = maybe_lock_path;
                break;
            } else {
                curr_path = parent;
            }
        }

        if !lock_path.is_file() {
            return Err(anyhow::anyhow!("Cargo.lock not found"));
        }
    }

    println!("cargo:warning=Found Cargo.lock at {}", lock_path.display());

    // strip any comments for serialization and the rust compiler header
    let reader = BufReader::new(std::fs::File::open(&lock_path)?).lines();
    let toml_string = reader
        .skip(4)
        .map(|line| line.context("Failed to readline from cargo lock file"))
        .map(|line| line.map(|line| line + "\n"))
        .collect::<Result<String>>()?;

    let locked = toml::from_str::<LockFile>(&toml_string)?;

    let vm_package = locked
        .package
        .iter()
        .find(|p| p.name == "sp1-zkvm")
        .ok_or_else(|| anyhow::anyhow!("sp1-zkvm not found in lock file!"))?;

    let sp1_sdk = locked
        .package
        .iter()
        .find(|p| p.name == "sp1-sdk")
        .ok_or_else(|| anyhow::anyhow!("sp1-sdk not found in lock file!"))?;

    // print these just to be useful
    let toolchain_version = env!("CARGO_PKG_VERSION");
    println!("cargo:warning=Locked version of sp1-zkvm is {}", vm_package.version);
    println!("cargo:warning=Locked version of sp1-sdk is {}", sp1_sdk.version);
    println!("cargo:warning=Current toolchain version = {}", toolchain_version);

    let vm_version = semver::Version::parse(&vm_package.version)?;
    let toolchain_version = semver::Version::parse(toolchain_version)?;
    let sp1_sdk_version = semver::Version::parse(&sp1_sdk.version)?;

    if vm_version.major != toolchain_version.major
        || vm_version.minor != toolchain_version.minor
        || sp1_sdk_version.major != toolchain_version.major
        || sp1_sdk_version.minor != toolchain_version.minor
    {
        return Err(anyhow::anyhow!(
            "Locked version of sp1-zkvm or sp1-sdk is incompatible with the current toolchain version"
        ));
    }

    Ok(())
}
