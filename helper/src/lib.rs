use chrono::Local;
use sp1_build::BuildArgs;
use std::{path::Path, process::ExitStatus};

fn current_datetime() -> String {
    let now = Local::now();
    now.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Re-run the cargo command if the Cargo.toml or Cargo.lock file changes.
pub fn cargo_rerun_if_changed(path: &str) -> (&Path, String) {
    println!("path: {:?}", path);
    let program_dir = std::path::Path::new(path);

    // Tell cargo to rerun the script if program/{src, Cargo.toml, Cargo.lock} or any dependency
    // changes.
    let metadata_file = program_dir.join("Cargo.toml");
    let mut metadata_cmd = cargo_metadata::MetadataCommand::new();
    let metadata = metadata_cmd.manifest_path(metadata_file).exec().unwrap();

    // TODO: This will re-run more often as the program directory's Cargo.lock is intertwined with
    // the workspace's Cargo.lock.
    println!(
        "cargo:rerun-if-changed={}",
        metadata.workspace_root.join("Cargo.lock").as_str()
    );

    for package in &metadata.packages {
        println!("cargo:rerun-if-changed={}", package.manifest_path.as_str());
    }

    // Print a message so the user knows that their program was built. Cargo caches warnings emitted
    // from build scripts, so we'll print the date/time when the program was built.
    let root_package = metadata.root_package();
    let root_package_name = root_package
        .as_ref()
        .map(|p| p.name.as_str())
        .unwrap_or("Program");
    println!(
        "cargo:warning={} built at {}",
        root_package_name,
        current_datetime()
    );

    (program_dir, root_package_name.to_string())
}

/// Builds the program if the program at path, or one of its dependencies, changes.
/// Note: This function is kept for backwards compatibility.
pub fn build_program(path: &str) {
    // Activate the build command if the dependencies change.
    let (program_dir, _) = cargo_rerun_if_changed(path);

    let _ = execute_build_cmd(&program_dir, None);
}

/// Builds the program with the given arguments if the program at path, or one of its dependencies,
/// changes.
pub fn build_program_with_args(path: &str, args: BuildArgs) {
    // Activate the build command if the dependencies change.
    let (program_dir, _) = cargo_rerun_if_changed(path);

    let _ = execute_build_cmd(&program_dir, Some(args));
}

/// Add the `cargo prove build` arguments to the `command_args` vec. This is useful when adding
/// the `cargo prove build` arguments to an existing command.
pub fn add_cargo_prove_build_args(
    command_args: &mut Vec<String>,
    prove_args: BuildArgs,
    ignore_docker: bool,
) {
    if prove_args.docker && !ignore_docker {
        command_args.push("--docker".to_string());
    }
    if prove_args.ignore_rust_version {
        command_args.push("--ignore-rust-version".to_string());
    }
    if !prove_args.features.is_empty() {
        for feature in prove_args.features {
            command_args.push("--features".to_string());
            command_args.push(feature);
        }
    }
    if let Some(binary) = &prove_args.binary {
        command_args.push("--binary".to_string());
        command_args.push(binary.clone());
    }
    if let Some(elf) = &prove_args.elf {
        command_args.push("--elf".to_string());
        command_args.push(elf.clone());
    }
}

/// Executes the `cargo prove build` command in the program directory. If there are any cargo prove
/// build arguments, they are added to the command.
fn execute_build_cmd(
    program_dir: &impl AsRef<std::path::Path>,
    args: Option<BuildArgs>,
) -> Result<std::process::ExitStatus, std::io::Error> {
    // Check if RUSTC_WORKSPACE_WRAPPER is set to clippy-driver (i.e. if `cargo clippy` is the current
    // compiler). If so, don't execute `cargo prove build` because it breaks rust-analyzer's `cargo clippy` feature.
    let is_clippy_driver = std::env::var("RUSTC_WORKSPACE_WRAPPER")
        .map(|val| val.contains("clippy-driver"))
        .unwrap_or(false);
    if is_clippy_driver {
        println!("cargo:warning=Skipping build due to clippy invocation.");
        return Ok(std::process::ExitStatus::default());
    }

    let path_output = if let Some(args) = args {
        sp1_build::build_program(&args, Some(program_dir.as_ref().to_path_buf()))
    } else {
        sp1_build::build_program(
            &BuildArgs::default(),
            Some(program_dir.as_ref().to_path_buf()),
        )
    };

    if let Err(e) = path_output {
        eprintln!("Error: {}", e);
    }

    Ok(ExitStatus::default())
}
