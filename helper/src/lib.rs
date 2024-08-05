mod docker;
mod program;

use cargo_metadata::Metadata;
use chrono::Local;
pub use program::execute_build_program;
pub(crate) use program::HELPER_TARGET_SUBDIR;
use std::path::Path;

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

// Implement default args to match clap defaults.
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

fn current_datetime() -> String {
    let now = Local::now();
    now.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Re-run the cargo command if the Cargo.toml or Cargo.lock file changes.
fn cargo_rerun_if_changed(metadata: &Metadata, program_dir: &Path) {
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
            println!(
                "cargo::rerun-if-changed={}",
                dir.canonicalize().unwrap().display()
            );
        }
    }

    // Re-run the build script if the workspace root's Cargo.lock changes. If the program is its own
    // workspace, this will be the program's Cargo.lock.
    println!(
        "cargo:rerun-if-changed={}",
        metadata.workspace_root.join("Cargo.lock").as_str()
    );

    // Re-run if any local dependency changes.
    for package in &metadata.packages {
        for dependency in &package.dependencies {
            if let Some(path) = &dependency.path {
                println!("cargo:rerun-if-changed={}", path.as_str());
            }
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

/// Internal helper function to build the program with or without arguments.
fn build_program_internal(path: &str, args: Option<BuildArgs>) {
    // Get the root package name and metadata.
    let program_dir = std::path::Path::new(path);
    let metadata_file = program_dir.join("Cargo.toml");
    let mut metadata_cmd = cargo_metadata::MetadataCommand::new();
    let metadata = metadata_cmd.manifest_path(metadata_file).exec().unwrap();
    let root_package = metadata.root_package();
    let root_package_name = root_package
        .as_ref()
        .map(|p| p.name.as_str())
        .unwrap_or("Program");

    // Skip the program build if the SP1_SKIP_PROGRAM_BUILD environment variable is set to true.
    let skip_program_build = std::env::var("SP1_SKIP_PROGRAM_BUILD")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if skip_program_build {
        println!(
            "cargo:warning=Build skipped for {} at {} due to SP1_SKIP_PROGRAM_BUILD flag",
            root_package_name,
            current_datetime()
        );
        return;
    }

    // Activate the build command if the dependencies change.
    cargo_rerun_if_changed(&metadata, program_dir);

    // Check if RUSTC_WORKSPACE_WRAPPER is set to clippy-driver (i.e. if `cargo clippy` is the current
    // compiler). If so, don't execute `cargo prove build` because it breaks rust-analyzer's `cargo clippy` feature.
    let is_clippy_driver = std::env::var("RUSTC_WORKSPACE_WRAPPER")
        .map(|val| val.contains("clippy-driver"))
        .unwrap_or(false);
    if is_clippy_driver {
        println!("cargo:warning=Skipping build due to clippy invocation.");
    }

    // Build the program with the given arguments.
    let build_args = args.unwrap_or_default();
    let path_output =
        crate::program::execute_build_program(&build_args, Some(program_dir.to_path_buf()));
    if let Err(err) = path_output {
        panic!("Failed to build SP1 program: {}.", err);
    }

    println!(
        "cargo:warning={} built at {}",
        root_package_name,
        current_datetime()
    );
}
