#[cfg(feature = "clap")]
use clap::Parser;
use std::{
    fs,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{exit, ChildStderr, ChildStdout, Command, Stdio},
    thread,
};

use anyhow::{Context, Result};
use cargo_metadata::camino::Utf8PathBuf;

#[derive(Default, Clone)]
// Conditionally derive the `Parser` trait if the `clap` feature is enabled. This is useful
// for keeping the binary size smaller.
#[cfg_attr(feature = "clap", derive(Parser))]
/// `BuildArgs` is a struct that holds various arguments used for building a program.
///
/// This struct can be used to configure the build process, including options for using Docker,
/// specifying binary and ELF names, ignoring Rust version checks, and enabling specific features.
///
/// # Fields
///
/// * `docker` - A boolean flag to indicate whether to use Docker for reproducible builds.
/// * `tag` - A string specifying the Docker image tag to use when building with Docker. Defaults to "latest".
/// * `features` - A vector of strings specifying features to build with.
/// * `ignore_rust_version` - A boolean flag to ignore Rust version checks.
/// * `binary` - An optional string to specify the name of the binary if building a binary.
/// * `elf_name` - An optional string to specify the name of the ELF binary.
/// * `output_directory` - An optional string to specify the directory to place the built program relative to the program directory.
pub struct BuildArgs {
    #[cfg_attr(
        feature = "clap",
        clap(long, action, help = "Build using Docker for reproducible builds.")
    )]
    pub docker: bool,
    #[cfg_attr(
        feature = "clap",
        clap(
            long,
            help = "The ghcr.io/succinctlabs/sp1 image tag to use when building with docker.",
            default_value = "latest"
        )
    )]
    pub tag: String,
    #[cfg_attr(
        feature = "clap",
        clap(long, action, value_delimiter = ',', help = "Build with features.")
    )]
    pub features: Vec<String>,
    #[cfg_attr(
        feature = "clap",
        clap(long, action, help = "Ignore Rust version check.")
    )]
    pub ignore_rust_version: bool,
    #[cfg_attr(
        feature = "clap",
        clap(
            long,
            action,
            help = "If building a binary, specify the name.",
            default_value = ""
        )
    )]
    pub binary: String,
    #[cfg_attr(
        feature = "clap",
        clap(long, action, help = "ELF binary name.", default_value = "")
    )]
    pub elf_name: String,
    #[cfg_attr(
        feature = "clap",
        clap(
            long,
            action,
            help = "The output directory for the built program.",
            default_value = ""
        )
    )]
    pub output_directory: String,
}

/// Uses SP1_DOCKER_IMAGE environment variable if set, otherwise constructs the image to use based
/// on the provided tag.
fn get_docker_image(tag: &str) -> String {
    std::env::var("SP1_DOCKER_IMAGE").unwrap_or_else(|_| {
        let image_base = "ghcr.io/succinctlabs/sp1";
        format!("{}:{}", image_base, tag)
    })
}

/// Modify the command to build the program in the docker container. Mounts the entire workspace
/// and sets the working directory to the program directory.
fn get_docker_cmd(
    command: &mut Command,
    args: &BuildArgs,
    workspace_root: &Utf8PathBuf,
    program_dir: &Utf8PathBuf,
    build_target: String,
) -> Result<()> {
    let image = get_docker_image(&args.tag);

    // Check if docker is installed and running.
    let docker_check = Command::new("docker")
        .args(["info"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("failed to run docker command")?;
    if !docker_check.success() {
        eprintln!("docker is not installed or not running: https://docs.docker.com/get-docker/");
        exit(1);
    }

    // Mount the entire workspace, and set the working directory to the program dir.
    let workspace_root_path = format!("{}:/root/program", workspace_root);
    let program_dir_path = format!(
        "/root/program/{}",
        program_dir.strip_prefix(workspace_root).unwrap()
    );
    let rust_flags = [
        "-C".to_string(),
        "passes=loweratomic".to_string(),
        "-C".to_string(),
        "link-arg=-Ttext=0x00200800".to_string(),
        "-C".to_string(),
        "panic=abort".to_string(),
    ];
    let mut docker_args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "--platform".to_string(),
        "linux/amd64".to_string(),
        "-v".to_string(),
        workspace_root_path,
        "-w".to_string(),
        program_dir_path,
        "-e".to_string(),
        "RUSTUP_TOOLCHAIN=succinct".to_string(),
        "-e".to_string(),
        format!("CARGO_ENCODED_RUSTFLAGS={}", rust_flags.join("\x1f")),
        image,
        "--entrypoint".to_string(),
        "cargo".to_string(),
    ];

    docker_args.extend_from_slice(&[
        "build".to_string(),
        "--release".to_string(),
        "--target".to_string(),
        build_target,
    ]);

    if args.ignore_rust_version {
        docker_args.push("--ignore-rust-version".to_string());
    }

    if !args.binary.is_empty() {
        docker_args.push("--bin".to_string());
        docker_args.push(args.binary.clone());
    }

    if !args.features.is_empty() {
        docker_args.push("--features".to_string());
        docker_args.push(args.features.join(","));
    }

    // Ensure the Cargo.lock doesn't update.
    docker_args.push("--locked".to_string());

    // Set the arguments and remove RUSTC from the environment to avoid ensure the correct
    // version is used.
    command.current_dir(program_dir.clone()).args(&docker_args);
    Ok(())
}

/// Modify the command to build the program in the local environment.
fn get_build_cmd(
    command: &mut Command,
    args: &BuildArgs,
    program_dir: &Utf8PathBuf,
    build_target: String,
) -> Result<()> {
    let rust_flags = [
        "-C".to_string(),
        "passes=loweratomic".to_string(),
        "-C".to_string(),
        "link-arg=-Ttext=0x00200800".to_string(),
        "-C".to_string(),
        "panic=abort".to_string(),
    ];

    let mut cargo_args = vec![
        "build".to_string(),
        "--release".to_string(),
        "--target".to_string(),
        build_target,
    ];

    if args.ignore_rust_version {
        cargo_args.push("--ignore-rust-version".to_string());
    }

    if !args.binary.is_empty() {
        cargo_args.push("--bin".to_string());
        cargo_args.push(args.binary.clone());
    }

    if !args.features.is_empty() {
        cargo_args.push("--features".to_string());
        cargo_args.push(args.features.join(","));
    }

    // Ensure the Cargo.lock doesn't update.
    cargo_args.push("--locked".to_string());

    command
        .current_dir(program_dir.clone())
        .env("RUSTUP_TOOLCHAIN", "succinct")
        .env("CARGO_ENCODED_RUSTFLAGS", rust_flags.join("\x1f"))
        .args(&cargo_args);
    Ok(())
}

/// Add the [sp1] or [docker] prefix to the output of the child process depending on the context.
fn handle_cmd_output(
    stdout: BufReader<ChildStdout>,
    stderr: BufReader<ChildStderr>,
    build_with_helper: bool,
    docker: bool,
) {
    let msg = match (build_with_helper, docker) {
        (true, true) => "[sp1] [docker] ",
        (true, false) => "[sp1] ",
        (false, true) => "[docker] ",
        (false, false) => "",
    };
    // Pipe stdout and stderr to the parent process with [docker] prefix
    let stdout_handle = thread::spawn(move || {
        stdout.lines().for_each(|line| {
            println!("{} {}", msg, line.unwrap());
        });
    });
    stderr.lines().for_each(|line| {
        eprintln!("{} {}", msg, line.unwrap());
    });

    stdout_handle.join().unwrap();
}

/// Build a program with the specified BuildArgs. The `program_dir` is specified as an argument when
/// the program is built via `build_program` in sp1-helper.
///
/// # Arguments
///
/// * `args` - A reference to a `BuildArgs` struct that holds various arguments used for building the program.
/// * `program_dir` - An optional `PathBuf` specifying the directory of the program to be built.
///
/// # Returns
///
/// * `Result<Utf8PathBuf>` - The path to the built program as a `Utf8PathBuf` on success, or an error on failure.
pub fn build_program(args: &BuildArgs, program_dir: Option<PathBuf>) -> Result<Utf8PathBuf> {
    // If the program directory is specified, this function was called by sp1-helper.
    let is_helper = program_dir.is_some();

    // If the program directory is not specified, use the current directory.
    let program_dir = program_dir
        .unwrap_or_else(|| std::env::current_dir().expect("Failed to get current directory."));
    let program_dir: Utf8PathBuf = program_dir
        .try_into()
        .expect("Failed to convert PathBuf to Utf8PathBuf");

    // The root package name corresponds to the package name of the current directory.
    let metadata_cmd = cargo_metadata::MetadataCommand::new();
    let metadata = metadata_cmd.exec().unwrap();
    let root_package = metadata.root_package();
    let root_package_name = root_package.as_ref().map(|p| &p.name);

    // Get the command corresponding to Docker or local build.
    let build_target = "riscv32im-succinct-zkvm-elf".to_string();
    let mut cmd = if args.docker {
        let mut docker_cmd = Command::new("docker");
        get_docker_cmd(
            &mut docker_cmd,
            args,
            &metadata.workspace_root,
            &program_dir,
            build_target.clone(),
        )?;
        docker_cmd
    } else {
        let mut build_cmd = Command::new("cargo");
        get_build_cmd(&mut build_cmd, args, &program_dir, build_target.clone())?;
        build_cmd
    };

    // Strip the Rustc configuration if this is called by sp1-helper, otherwise it will attempt to
    // compile the SP1 program with the toolchain of the normal build process, rather than the
    // Succinct toolchain.
    if is_helper {
        cmd.env_remove("RUSTC");
    }

    // Add necessary tags for stdout and stderr from the command.
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn command")?;
    let stdout = BufReader::new(child.stdout.take().unwrap());
    let stderr = BufReader::new(child.stderr.take().unwrap());
    handle_cmd_output(stdout, stderr, is_helper, args.docker);
    let result = child.wait()?;
    if !result.success() {
        // Error message is already printed by cargo.
        exit(result.code().unwrap_or(1))
    }

    // The ELF is written to a target folder specified by the program's package.
    let original_elf_path = metadata
        .target_directory
        .join(build_target.clone())
        .join("release")
        .join(root_package_name.unwrap());

    // The order of precedence for the ELF name is:
    // 1. --elf_name flag
    // 2. --binary flag (binary name + -elf suffix)
    // 3. default (root package name)
    let elf_name = if !args.elf_name.is_empty() {
        args.elf_name.clone()
    } else if !args.binary.is_empty() {
        format!("{}-elf", args.binary.clone())
    } else {
        root_package_name.unwrap().to_string()
    };

    let elf_dir = if !args.output_directory.is_empty() {
        program_dir.join(args.output_directory.clone())
    } else {
        program_dir.join("elf")
    };
    fs::create_dir_all(&elf_dir)?;
    let result_elf_path = elf_dir.join(elf_name);

    println!("cargo:warning=original_elf_path: {}", original_elf_path);
    println!("cargo:warning=result_elf_path: {}", result_elf_path);
    // Copy the ELF to the specified output directory.
    fs::copy(original_elf_path, &result_elf_path)?;

    Ok(result_elf_path)
}
