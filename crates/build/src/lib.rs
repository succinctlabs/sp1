mod build;
mod command;
mod utils;
use build::build_program_internal;
pub use build::{execute_build_program, generate_elf_paths};
pub use command::TOOLCHAIN_NAME;

use clap::Parser;

// todo!(n): Remove this for v4 and change it back to `SP1_CIRCUIT_VERSION`.
// This is convenient because everything else (circuit artifacts) use rc.3 still.
/// This is the minimum version of the Docker image that supports the 1.82 `succinct` toolchain.
const MIN_SP1_1_82_SUPPORT_TAG: &str = "v4.0.0-rc.10";

const BUILD_TARGET: &str = "riscv32im-succinct-zkvm-elf";
const HELPER_TARGET_SUBDIR: &str = "elf-compilation";

/// Compile an SP1 program.
///
/// Additional arguments are useful for configuring the build process, including options for using
/// Docker, specifying binary and ELF names, ignoring Rust version checks, and enabling specific
/// features.
#[derive(Clone, Parser, Debug)]
pub struct BuildArgs {
    #[clap(
        long,
        action,
        help = "Run compilation using a Docker container for reproducible builds."
    )]
    pub docker: bool,
    #[clap(
        long,
        help = "The ghcr.io/succinctlabs/sp1 image tag to use when building with Docker.",
        default_value = MIN_SP1_1_82_SUPPORT_TAG
    )]
    pub tag: String,
    #[clap(
        long,
        action,
        value_delimiter = ',',
        help = "Space or comma separated list of features to activate"
    )]
    pub features: Vec<String>,
    #[clap(
        long,
        action,
        value_delimiter = ',',
        help = "Space or comma separated list of extra flags to invokes `rustc` with"
    )]
    pub rustflags: Vec<String>,
    #[clap(long, action, help = "Do not activate the `default` feature")]
    pub no_default_features: bool,
    #[clap(long, action, help = "Ignore `rust-version` specification in packages")]
    pub ignore_rust_version: bool,
    #[clap(long, action, help = "Assert that `Cargo.lock` will remain unchanged")]
    pub locked: bool,
    #[clap(
        short,
        long,
        action,
        help = "Build only the specified packages",
        num_args = 1..
    )]
    pub packages: Vec<String>,
    #[clap(
        alias = "bin",
        long,
        action,
        help = "Build only the specified binaries",
        num_args = 1..
    )]
    pub binaries: Vec<String>,
    #[clap(long, action, help = "ELF binary name")]
    pub elf_name: Option<String>,
    #[clap(alias = "out-dir", long, action, help = "Copy the compiled ELF to this directory")]
    pub output_directory: Option<String>,

    #[clap(
        alias = "workspace-dir",
        long,
        action,
        help = "The top level directory to be used in the docker invocation."
    )]
    pub workspace_directory: Option<String>,
}

// Implement default args to match clap defaults.
impl Default for BuildArgs {
    fn default() -> Self {
        Self {
            docker: false,
            tag: MIN_SP1_1_82_SUPPORT_TAG.to_string(),
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
