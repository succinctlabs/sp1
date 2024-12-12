mod build;
mod command;
mod utils;
use build::build_program_internal;
pub use build::execute_build_program;

use clap::Parser;

const BUILD_TARGET: &str = "riscv32im-succinct-zkvm-elf";
const DEFAULT_TAG: &str = "latest";
const DEFAULT_OUTPUT_DIR: &str = "elf";
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
        default_value = DEFAULT_TAG
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
        alias = "bin",
        long,
        action,
        help = "Build only the specified binary",
        default_value = ""
    )]
    pub binary: String,
    #[clap(long, action, help = "ELF binary name", default_value = "")]
    pub elf_name: String,
    #[clap(
        alias = "out-dir",
        long,
        action,
        help = "Copy the compiled ELF to this directory",
        default_value = DEFAULT_OUTPUT_DIR
    )]
    pub output_directory: String,
}

// Implement default args to match clap defaults.
impl Default for BuildArgs {
    fn default() -> Self {
        Self {
            docker: false,
            tag: DEFAULT_TAG.to_string(),
            features: vec![],
            rustflags: vec![],
            ignore_rust_version: false,
            binary: "".to_string(),
            elf_name: "".to_string(),
            output_directory: DEFAULT_OUTPUT_DIR.to_string(),
            locked: false,
            no_default_features: false,
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
