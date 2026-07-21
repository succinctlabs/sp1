mod build;
mod command;
mod utils;

use std::env;
use std::path::{Path, PathBuf};

use build::build_program_internal;
pub use build::{execute_build_program, generate_elf_paths};
pub use command::TOOLCHAIN_NAME;

pub use sp1_primitives::types::Elf;

use clap::{Parser, ValueEnum};

const DEFAULT_DOCKER_TAG: &str = concat!("v", env!("CARGO_PKG_VERSION"));
pub const DEFAULT_TARGET: &str = "riscv64im-succinct-zkvm-elf";
const HELPER_TARGET_SUBDIR: &str = "elf-compilation";

/// Clang/clang++ command-line flags for compiling C/C++ for SP1's
/// `riscv64im-succinct-zkvm-elf` target.
///
/// Useful for build scripts that want to bring C code into an SP1 guest
/// (either as a pure-C guest linked against a libc-style shim, or as
/// FFI inside a Rust guest). Pair with [`find_lld`] to drive a clang +
/// ld.lld pipeline by hand, or use [`build_program_staticlib`] +
/// [`build_program`] for the canonical Rust-staticlib path.
pub const CLANG_FLAGS: &[&str] = &[
    "--target=riscv64-unknown-none-elf",
    "-march=rv64im",
    "-mabi=lp64",
    "-ffreestanding",
    "-fno-builtin",
    "-fno-stack-protector",
    "-nostdlibinc",
];

/// Locate `ld.lld`, preferring a system `PATH` install and falling
/// back to the bundled copy in any installed SP1 toolchain
/// (`~/.sp1/toolchains/*/lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld/ld.lld`).
///
/// Useful for build scripts that need to link C objects against an
/// SP1 staticlib without requiring a system-wide `lld` install.
pub fn find_lld() -> Option<PathBuf> {
    use std::process::Command;
    if Command::new("ld.lld").arg("--version").output().is_ok_and(|o| o.status.success()) {
        return Some(PathBuf::from("ld.lld"));
    }
    let home = std::env::var_os("HOME")?;
    let toolchains = Path::new(&home).join(".sp1/toolchains");
    for entry in std::fs::read_dir(&toolchains).ok()?.flatten() {
        let candidate = entry.path().join("lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld/ld.lld");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Build a `crate-type = ["staticlib"]` crate for SP1 via
/// [`build_program`] and return the path to the resulting `.a`.
///
/// `build_program` is bin-oriented and surfaces ELFs via `SP1_ELF_*`
/// env vars; for staticlibs the artifact path follows a fixed
/// convention under SP1's helper target subdirectory, so this wrapper
/// just runs the build and assembles the path from cargo metadata.
///
/// Path layout: `<crate>/target/elf-compilation/<triple>/release/lib<lib_name>.a`.
///
/// Panics if cargo metadata can't be read or the staticlib doesn't
/// exist after the build.
pub fn build_program_staticlib(path: &str) -> PathBuf {
    let manifest = Path::new(path).join("Cargo.toml");
    let mut metadata_cmd = cargo_metadata::MetadataCommand::new();
    let metadata = metadata_cmd.manifest_path(&manifest).exec().unwrap_or_else(|e| {
        panic!("failed to read cargo metadata from {}: {e}", manifest.display())
    });
    let root_package = metadata
        .root_package()
        .unwrap_or_else(|| panic!("no root package at {}", manifest.display()));
    let lib_target = root_package
        .targets
        .iter()
        .find(|t| t.kind.iter().any(|k| k == "staticlib"))
        .unwrap_or_else(|| panic!("crate {} has no `staticlib` target", root_package.name));

    build_program(path);

    let staticlib = metadata
        .target_directory
        .join(HELPER_TARGET_SUBDIR)
        .join(DEFAULT_TARGET)
        .join("release")
        .join(format!("lib{}.a", lib_target.name));
    if !staticlib.as_std_path().exists() {
        panic!(
            "expected staticlib at {} after `build_program` — did the build fail silently?",
            staticlib
        );
    }
    staticlib.into_std_path_buf()
}

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

    #[arg(
        long,
        action,
        help = "Disable Docker volume caching for cargo registry and git dependencies."
    )]
    pub no_docker_cache: bool,
}

// Implement default args to match clap defaults.
impl Default for BuildArgs {
    #[allow(clippy::uninlined_format_args)]
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
            no_docker_cache: false,
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

// /// Returns the verification key for the provided program.
// ///
// /// # Arguments
// ///
// /// * `path` - A string slice that holds the path to the program directory.
// /// * `target_name` - A string slice that holds the binary target.
// ///
// /// Note: If used in a script `build.rs`, this function should be called *after*
// [`build_program`] /// to returns the vkey corresponding to the latest program version which has
// just been compiled. pub async fn vkey(path: &str, target_name: &str) -> String {
//     let program_dir = std::path::Path::new(path);
//     let metadata_file = program_dir.join("Cargo.toml");
//     let mut metadata_cmd = cargo_metadata::MetadataCommand::new();
//     let metadata = metadata_cmd.manifest_path(metadata_file).exec().unwrap();
//     let target_elf_paths =
//         generate_elf_paths(&metadata, None).expect("failed to collect target ELF paths");
//     let (_, path) =
//         target_elf_paths.iter().find(|(t, _)| t == target_name).expect("failed to find the
// target");     let prover = Local
//     let mut file = File::open(path).unwrap();
//     let mut elf = Vec::new();

//     file.read_to_end(&mut elf).unwrap();
//     let (_, _, vk) = prover.core().setup(&elf).await;
//     vk.bytes32()
// }

// /// Returns the verification keys for the provided programs in a [`HashMap`] with the target
// names /// as keys and vkeys as values.
// ///
// /// # Arguments
// ///
// /// * `path` - A string slice that holds the path to the program directory.
// /// * `args` - A [`BuildArgs`] struct that contains various build configuration options.
// ///
// /// Note: If used in a script `build.rs`, this function should be called *after*
// [`build_program`] /// to returns the vkey corresponding to the latest program version which has
// just been compiled. pub fn vkeys(path: &str, args: BuildArgs) -> HashMap<String, String> {
//     let program_dir = std::path::Path::new(path);
//     let metadata_file = program_dir.join("Cargo.toml");
//     let mut metadata_cmd = cargo_metadata::MetadataCommand::new();
//     let metadata = metadata_cmd.manifest_path(metadata_file).exec().unwrap();
//     let target_elf_paths =
//         generate_elf_paths(&metadata, Some(&args)).expect("failed to collect target ELF paths");
//     let prover = SP1Prover::<CpuProverComponents>::new();

//     target_elf_paths
//         .into_iter()
//         .map(|(target_name, elf_path)| {
//             let mut file = File::open(elf_path).unwrap();
//             let mut elf = Vec::new();
//             file.read_to_end(&mut elf).unwrap();

//             let (_, _, _, vk) = prover.setup(&elf);
//             let vk = vk.bytes32();

//             (target_name, vk)
//         })
//         .collect()
// }

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
        // TODO: --all-features forces this branch. feature flags may not be the right solution here
        $crate::Elf::Static(include_bytes!(env!(concat!("SP1_ELF_", $arg))))
    }};
}
