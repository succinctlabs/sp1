use std::path::PathBuf;

use anyhow::Result;
use cargo_metadata::camino::Utf8PathBuf;

use crate::{
    command::{docker::create_docker_command, local::create_local_command, utils::execute_command},
    utils::{cargo_rerun_if_changed, current_datetime},
    BuildArgs, WarningLevel, BUILD_TARGET, HELPER_TARGET_SUBDIR,
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
        create_local_command(args, &program_dir, &program_metadata)?
    };

    let target_elf_paths = generate_elf_paths(&program_metadata, Some(args))?;

    if target_elf_paths.len() > 1 && args.elf_name.is_some() {
        anyhow::bail!("--elf-name is not supported when --output-directory is used and multiple ELFs are built.");
    }

    execute_command(cmd, args.docker)?;

    if let Some(output_directory) = &args.output_directory {
        // The path to the output directory, maybe relative or absolute.
        let output_directory = PathBuf::from(output_directory);

        // Ensure the output directory is a directory. If it doesnt exist, this is false.
        if output_directory.is_file() {
            anyhow::bail!("--output-directory is a file.");
        }

        // Ensure the output directory exists.
        std::fs::create_dir_all(&output_directory)?;

        // Copy the ELF files to the output directory.
        for (_, elf_path) in target_elf_paths.iter() {
            let elf_path = elf_path.to_path_buf();
            let elf_name = elf_path.file_name().expect("ELF path has a file name");
            let output_path = output_directory.join(args.elf_name.as_deref().unwrap_or(elf_name));

            std::fs::copy(&elf_path, &output_path)?;
        }
    }

    print_elf_paths_cargo_directives(&target_elf_paths);

    Ok(target_elf_paths)
}

/// Internal helper function to build the program with or without arguments.
pub(crate) fn build_program_internal(path: &str, args: Option<BuildArgs>) {
    // Get the root package name and metadata.
    let program_dir = std::path::Path::new(path);
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
    let path_output = if let Some(args) = &args {
        execute_build_program(args, Some(program_dir.to_path_buf()))
    } else {
        execute_build_program(&BuildArgs::default(), Some(program_dir.to_path_buf()))
    };
    if let Err(err) = path_output {
        panic!("Failed to build SP1 program: {}.", err);
    }

    if args.map(|args| matches!(args.warning_level, WarningLevel::All)).unwrap_or(true) {
        println!("cargo:warning={} built at {}", root_package_name, current_datetime());
    }
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
