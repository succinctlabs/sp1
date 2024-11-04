mod build;
mod command;
mod utils;

use build::build_program_internal;
pub use build::execute_build_program;
use clap::Parser;

// Constants
const BUILD_TARGET: &str = "riscv32im-succinct-zkvm-elf";
const DEFAULT_TAG: &str = "latest";
const DEFAULT_OUTPUT_DIR: &str = "elf";
const HELPER_TARGET_SUBDIR: &str = "elf-compilation";

/// Configuration for compiling an SP1 program
#[derive(Clone, Parser, Debug)]
pub struct BuildArgs {
    /// Run compilation in Docker for reproducible builds
    #[clap(long, action)]
    pub docker: bool,

    /// Docker image tag (ghcr.io/succinctlabs/sp1)
    #[clap(long, default_value = DEFAULT_TAG)]
    pub tag: String,

    /// Cargo features to activate (comma-separated)
    #[clap(long, value_delimiter = ',')]
    pub features: Vec<String>,

    /// Additional rustc flags (comma-separated)
    #[clap(long, value_delimiter = ',')]
    pub rustflags: Vec<String>,

    /// Disable default features
    #[clap(long, action)]
    pub no_default_features: bool,

    /// Skip rust-version check
    #[clap(long, action)]
    pub ignore_rust_version: bool,

    /// Require Cargo.lock is up-to-date
    #[clap(long, action)]
    pub locked: bool,

    /// Target binary name
    #[clap(alias = "bin", long, default_value = "")]
    pub binary: String,

    /// Output ELF name
    #[clap(long, default_value = "")]
    pub elf_name: String,

    /// Output directory for ELF
    #[clap(alias = "out-dir", long, default_value = DEFAULT_OUTPUT_DIR)]
    pub output_directory: String,
}

impl Default for BuildArgs {
    fn default() -> Self {
        Self {
            docker: false,
            tag: DEFAULT_TAG.to_string(),
            features: Vec::new(),
            rustflags: Vec::new(),
            ignore_rust_version: false,
            binary: String::new(),
            elf_name: String::new(),
            output_directory: DEFAULT_OUTPUT_DIR.to_string(),
            locked: false,
            no_default_features: false,
        }
    }
}

/// Builds program on source changes
/// 
/// Monitors program and dependencies for changes and rebuilds when necessary.
/// Set SP1_SKIP_PROGRAM_BUILD=true to skip building.
/// 
/// # Arguments
/// * `path` - Program directory path
pub fn build_program(path: &str) {
    build_program_internal(path, None)
}

/// Builds program with custom configuration
/// 
/// Similar to build_program() but accepts custom build arguments.
/// Set SP1_SKIP_PROGRAM_BUILD=true to skip building.
///
/// # Arguments
/// * `path` - Program directory path
/// * `args` - Build configuration options
pub fn build_program_with_args(path: &str, args: BuildArgs) {
    build_program_internal(path, Some(args))
}
