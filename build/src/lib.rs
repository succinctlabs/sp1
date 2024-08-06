mod build;
mod command;
mod utils;
use build::build_program_internal;
pub use build::execute_build_program;

use clap::Parser;

const BUILD_TARGET: &str = "riscv32im-succinct-zkvm-elf";
const DEFAULT_TAG: &str = "v1.1.0";
const DEFAULT_OUTPUT_DIR: &str = "elf";
const HELPER_TARGET_SUBDIR: &str = "elf-compilation";

/// [`BuildArgs`] is a struct that holds various arguments used for building a program.
///
/// This struct can be used to configure the build process, including options for using Docker,
/// specifying binary and ELF names, ignoring Rust version checks, and enabling specific features.
#[derive(Clone, Parser, Debug)]
pub struct BuildArgs {
    #[clap(long, action, help = "Build using Docker for reproducible builds.")]
    pub docker: bool,
    #[clap(
        long,
        help = "The ghcr.io/succinctlabs/sp1 image tag to use when building with docker.",
        default_value = DEFAULT_TAG
    )]
    pub tag: String,
    #[clap(long, action, value_delimiter = ',', help = "Build with features.")]
    pub features: Vec<String>,
    #[clap(long, action, help = "Ignore Rust version check.")]
    pub ignore_rust_version: bool,
    #[clap(
        alias = "bin",
        long,
        action,
        help = "If building a binary, specify the name.",
        default_value = ""
    )]
    pub binary: String,
    #[clap(long, action, help = "ELF binary name.", default_value = "")]
    pub elf_name: String,
    #[clap(
        long,
        action,
        help = "The output directory for the built program.",
        default_value = DEFAULT_OUTPUT_DIR
    )]
    pub output_directory: String,
    #[clap(
        long,
        action,
        help = "Lock the dependencies, ensures that Cargo.lock doesn't update."
    )]
    pub locked: bool,
    #[clap(long, action, help = "Build without default features.")]
    pub no_default_features: bool,
}

// Default arguments that match clap defaults.
impl Default for BuildArgs {
    fn default() -> Self {
        Self {
            docker: false,
            tag: DEFAULT_TAG.to_string(),
            features: vec![],
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
/// This function monitors the program and its dependencies for changes. If any changes are detected,
/// it triggers a rebuild of the program.
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
