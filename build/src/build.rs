use anyhow::Result;
use cargo_metadata::camino::Utf8PathBuf;
use std::path::PathBuf;

use crate::{
    command::{docker::create_docker_command, local::create_local_command, utils::execute_command},
    utils::{cargo_rerun_if_changed, copy_elf_to_output_dir, current_datetime},
    BuildArgs,
};

/// Build a program with the specified [`BuildArgs`]. The `program_dir` should be specified as an argument when the program
/// is built with a build script.
///
/// This function should be called when metadata caching is not desired and the build should always execute.
///
/// # Arguments
///
/// * `args` - A reference to a `BuildArgs` struct that holds various arguments used for building the program.
/// * `program_dir` - An optional `PathBuf` specifying the directory of the program to be built.
///
/// # Returns
///
/// * `Result<Utf8PathBuf>` - The path to the built program as a `Utf8PathBuf` on success, or an error on failure.
pub fn execute_build_program(
    args: &BuildArgs,
    program_dir: Option<PathBuf>,
) -> Result<Utf8PathBuf> {
    // If the program directory is not specified, use the current directory.
    let program_dir = program_dir
        .unwrap_or_else(|| std::env::current_dir().expect("Failed to get current directory."));
    let program_dir_path = program_dir.canonicalize()?;
    let program_dir: Utf8PathBuf = program_dir_path.try_into()?;

    // Get the program metadata.
    let program_metadata_file = program_dir.join("Cargo.toml");
    let mut program_metadata_cmd = cargo_metadata::MetadataCommand::new();
    let program_metadata = program_metadata_cmd
        .manifest_path(program_metadata_file)
        .exec()
        .expect("Failed to get program metadata. Confirm that the program directory is valid.");

    // Get the command corresponding to Docker or local build.
    let cmd = if args.docker {
        create_docker_command(args, &program_dir, &program_metadata)?
    } else {
        create_local_command(args, &program_dir, &program_metadata)
    };

    // Execute the command.
    execute_command(cmd, args.docker)?;

    // Copy the ELF to the specified output directory.
    copy_elf_to_output_dir(args, &program_metadata)
}

/// Internal helper function to build the program with or without arguments.
pub(crate) fn build_program_internal(path: &str, args: Option<BuildArgs>) {
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
    let canonicalized_program_dir = program_dir
        .canonicalize()
        .expect("Failed to canonicalize program directory");
    let path_output = execute_build_program(&build_args, Some(canonicalized_program_dir));
    if let Err(err) = path_output {
        panic!("Failed to build SP1 program: {}.", err);
    }

    println!(
        "cargo:warning={} built at {}",
        root_package_name,
        current_datetime()
    );
}
