use chrono::Local;
pub use sp1_build::BuildArgs;
use std::{path::Path, process::ExitStatus};

fn current_datetime() -> String {
    let now = Local::now();
    now.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Re-run the cargo command if the Cargo.toml or Cargo.lock file changes. Note: SP1_SKIP_PROGRAM_BUILD
/// environment variable can be set to true to skip the program build.
fn cargo_rerun_if_changed(path: &str) -> (&Path, String) {
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
        return (program_dir, root_package_name.to_string());
    }

    // Re-run the build script if program/{src, Cargo.toml, Cargo.lock} or any dependency changes.
    println!(
        "cargo:rerun-if-changed={}",
        metadata.workspace_root.join("Cargo.lock").as_str()
    );

    for package in &metadata.packages {
        println!("cargo:rerun-if-changed={}", package.manifest_path.as_str());
    }

    (program_dir, root_package_name.to_string())
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

    // Build the program with the given arguments.
    let path_output = if let Some(args) = args {
        sp1_build::build_program(&args, Some(program_dir.as_ref().to_path_buf()))
    } else {
        sp1_build::build_program(
            &BuildArgs::default(),
            Some(program_dir.as_ref().to_path_buf()),
        )
    };
    if let Err(err) = path_output {
        eprintln!("Failed to build program: {}", err);
    }

    Ok(ExitStatus::default())
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
/// # Example
///
/// ```no_run
/// use sp1_helper::build_program;
///
/// build_program("../path/to/program");
/// ```
///
/// This function is useful for automatically rebuilding the program during development
/// when changes are made to the source code or its dependencies.
pub fn build_program(path: &str) {
    // Activate the build command if the dependencies change.
    let (program_dir, root_package_name) = cargo_rerun_if_changed(path);

    let _ = execute_build_cmd(&program_dir, None);

    println!(
        "cargo:warning={} built at {}",
        root_package_name,
        current_datetime()
    );
}

/// Builds the program with the given arguments if the program at path, or one of its dependencies,
/// changes.
///
/// # Arguments
///
/// * `path` - A string slice that holds the path to the program directory.
/// * `args` - A [`BuildArgs`] struct that contains various build configuration options.
///
/// # Example that builds the program in a docker container with the `feature1` feature enabled:
///
/// ```no_run
/// use sp1_helper::build_program_with_args;
/// use sp1_build::BuildArgs;
///
/// let args = BuildArgs {
///     docker: true,
///     features: vec!["feature1".to_string()],
///     ..Default::default()
/// };
///
/// build_program_with_args("../path/to/program", args);
/// ```
///
/// See [`BuildArgs`] for more details on available build options.
pub fn build_program_with_args(path: &str, args: BuildArgs) {
    // Activate the build command if the dependencies change.
    let (program_dir, root_package_name) = cargo_rerun_if_changed(path);

    let _ = execute_build_cmd(&program_dir, Some(args));

    println!(
        "cargo:warning={} built at {}",
        root_package_name,
        current_datetime()
    );
}
