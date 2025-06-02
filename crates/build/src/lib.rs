mod build;
mod command;
mod utils;
use std::{collections::HashMap, fs::File, io::Read};

use build::build_program_internal;
pub use build::{execute_build_program, generate_elf_paths};
pub use command::TOOLCHAIN_NAME;

use clap::{Parser, ValueEnum};
use sp1_prover::{components::CpuProverComponents, HashableKey, SP1Prover};

const DEFAULT_DOCKER_TAG: &str = concat!("v", env!("CARGO_PKG_VERSION"));
const BUILD_TARGET: &str = "riscv32im-succinct-zkvm-elf";
const HELPER_TARGET_SUBDIR: &str = "elf-compilation";

/// Controls the warning message verbosity in the build process.
#[derive(Clone, Copy, ValueEnum, Debug, Default)]
pub enum WarningLevel {
    /// Show all warning messages (default).
    #[default]
    All,
    /// Suppress non-essential warnings; show only critical stuff.
    Minimal,
}

/// Compile an SP1 program.
///
/// Additional arguments are useful for configuring the build process, including options for using
/// Docker, specifying binary and ELF names, ignoring Rust version checks, and enabling specific
/// features.
#[derive(Clone, Parser, Debug)]
pub struct BuildArgs {
    #[arg(
        long,
        action,
        help = "Run compilation using a Docker container for reproducible builds."
    )]
    pub docker: bool,
    #[arg(
        long,
        help = "The ghcr.io/succinctlabs/sp1 image tag to use when building with Docker.",
        default_value = DEFAULT_DOCKER_TAG
    )]
    pub tag: String,
    #[arg(
        long,
        action,
        value_delimiter = ',',
        help = "Space or comma separated list of features to activate"
    )]
    pub features: Vec<String>,
    #[arg(
        long,
        action,
        value_delimiter = ',',
        help = "Space or comma separated list of extra flags to invokes `rustc` with"
    )]
    pub rustflags: Vec<String>,
    #[arg(long, action, help = "Do not activate the `default` feature")]
    pub no_default_features: bool,
    #[arg(long, action, help = "Ignore `rust-version` specification in packages")]
    pub ignore_rust_version: bool,
    #[arg(long, action, help = "Assert that `Cargo.lock` will remain unchanged")]
    pub locked: bool,
    #[arg(
        short,
        long,
        action,
        help = "Build only the specified packages",
        num_args = 1..
    )]
    pub packages: Vec<String>,
    #[arg(
        alias = "bin",
        long,
        action,
        help = "Build only the specified binaries",
        num_args = 1..
    )]
    pub binaries: Vec<String>,
    #[arg(long, action, requires = "output_directory", help = "ELF binary name")]
    pub elf_name: Option<String>,
    #[arg(alias = "out-dir", long, action, help = "Copy the compiled ELF to this directory")]
    pub output_directory: Option<String>,

    #[arg(
        alias = "workspace-dir",
        long,
        action,
        help = "The top level directory to be used in the docker invocation."
    )]
    pub workspace_directory: Option<String>,

    #[arg(long, value_enum, default_value = "all", help = "Control warning message verbosity")]
    pub warning_level: WarningLevel,
}

// Implement default args to match clap defaults.
impl Default for BuildArgs {
    fn default() -> Self {
        Self {
            docker: false,
            tag: DEFAULT_DOCKER_TAG.to_string(),
            features: vec![],
            rustflags: vec![],
            ignore_rust_version: false,
            packages: vec![],
            binaries: vec![],
            elf_name: None,
            output_directory: None,
            locked: false,
            no_default_features: false,
            workspace_directory: None,
            warning_level: WarningLevel::All,
        }
    }
}

/// Builds the program if the program at the specified path, or one of its dependencies, changes.
///
/// This function monitors the program and its dependencies for changes. If any changes are
/// detected, it triggers a rebuild of the program.
///
/// # Arguments
///
/// * `path` - A string slice that holds the path to the program directory.
///
/// This function is useful for automatically rebuilding the program during development
/// when changes are made to the source code or its dependencies.
///
/// Set the `SP1_SKIP_PROGRAM_BUILD` environment variable to `true` to skip building the program.
pub fn build_program(path: &str) {
    build_program_internal(path, None)
}

/// Builds the program with the given arguments if the program at path, or one of its dependencies,
/// changes.
///
/// # Arguments
///
/// * `path` - A string slice that holds the path to the program directory.
/// * `args` - A [`BuildArgs`] struct that contains various build configuration options.
///
/// Set the `SP1_SKIP_PROGRAM_BUILD` environment variable to `true` to skip building the program.
pub fn build_program_with_args(path: &str, args: BuildArgs) {
    build_program_internal(path, Some(args))
}

/// Returns the verification key for the provided program.
///
/// # Arguments
///
/// * `path` - A string slice that holds the path to the program directory.
/// * `target_name` - A string slice that holds the binary target.
///
/// Note: If used in a script `build.rs`, this function should be called *after* [`build_program`]
/// to returns the vkey corresponding to the latest program version which has just been compiled.
pub fn vkey(path: &str, target_name: &str) -> String {
    let program_dir = std::path::Path::new(path);
    let metadata_file = program_dir.join("Cargo.toml");
    let mut metadata_cmd = cargo_metadata::MetadataCommand::new();
    let metadata = metadata_cmd.manifest_path(metadata_file).exec().unwrap();
    let target_elf_paths =
        generate_elf_paths(&metadata, None).expect("failed to collect target ELF paths");
    let (_, path) =
        target_elf_paths.iter().find(|(t, _)| t == target_name).expect("failed to find the target");
    let prover = SP1Prover::<CpuProverComponents>::new();
    let mut file = File::open(path).unwrap();
    let mut elf = Vec::new();

    file.read_to_end(&mut elf).unwrap();
    let (_, _, _, vk) = prover.setup(&elf);
    vk.bytes32()
}

/// Returns the verification keys for the provided programs in a [`HashMap`] with the target names
/// as keys and vkeys as values.
///
/// # Arguments
///
/// * `path` - A string slice that holds the path to the program directory.
/// * `args` - A [`BuildArgs`] struct that contains various build configuration options.
///
/// Note: If used in a script `build.rs`, this function should be called *after* [`build_program`]
/// to returns the vkey corresponding to the latest program version which has just been compiled.
pub fn vkeys(path: &str, args: BuildArgs) -> HashMap<String, String> {
    let program_dir = std::path::Path::new(path);
    let metadata_file = program_dir.join("Cargo.toml");
    let mut metadata_cmd = cargo_metadata::MetadataCommand::new();
    let metadata = metadata_cmd.manifest_path(metadata_file).exec().unwrap();
    let target_elf_paths =
        generate_elf_paths(&metadata, Some(&args)).expect("failed to collect target ELF paths");
    let prover = SP1Prover::<CpuProverComponents>::new();

    target_elf_paths
        .into_iter()
        .map(|(target_name, elf_path)| {
            let mut file = File::open(elf_path).unwrap();
            let mut elf = Vec::new();
            file.read_to_end(&mut elf).unwrap();

            let (_, _, _, vk) = prover.setup(&elf);
            let vk = vk.bytes32();

            (target_name, vk)
        })
        .collect()
}

/// Returns the raw ELF bytes by the zkVM program target name.
///
/// Note that this only works when using `sp1_build::build_program` or
/// `sp1_build::build_program_with_args` in a build script.
///
/// By default, the program target name is the same as the program crate name. However, this might
/// not be the case for non-standard project structures. For example, placing the entrypoint source
/// file at `src/bin/my_entry.rs` would result in the program target being named `my_entry`, in
/// which case the invocation should be `include_elf!("my_entry")` instead.
#[macro_export]
macro_rules! include_elf {
    ($arg:tt) => {{
        include_bytes!(env!(concat!("SP1_ELF_", $arg)))
    }};
}
