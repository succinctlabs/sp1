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
        clap(long, action, help = "Ignore Rust version check.")
    )]
    pub ignore_rust_version: bool,
    #[cfg_attr(
        feature = "clap",
        clap(long, action, help = "If building a binary, specify the name.")
    )]
    pub binary: Option<String>,
    #[cfg_attr(feature = "clap", clap(long, action, help = "ELF binary name."))]
    pub elf: Option<String>,
    #[cfg_attr(
        feature = "clap",
        clap(long, action, value_delimiter = ',', help = "Build with features.")
    )]
    pub features: Vec<String>,
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
) -> Result<()> {
    let image = get_docker_image(&args.tag);

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
    let mut child_args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "--platform".to_string(),
        "linux/amd64".to_string(),
        "-v".to_string(),
        workspace_root_path,
        "-w".to_string(),
        program_dir_path,
        image,
        "prove".to_string(),
        "build".to_string(),
    ];

    // Add the `cargo prove build` arguments to the child process command, while ignoring
    // `--docker`, as this command will be invoked in a docker container.
    add_cargo_prove_build_args(&mut child_args, args.clone(), true);

    // Set the arguments and remove RUSTC from the environment to avoid ensure the correct
    // version is used.
    command.args(&child_args).env_remove("RUSTC");
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

    // Add the `cargo prove build` arguments to the child process command, while ignoring
    // `--docker`, as we already know it's unused in this conditional.
    add_cargo_prove_build_args(&mut cargo_args, args.clone(), true);

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
    let msg = if build_with_helper && docker {
        "[sp1] [docker] "
    } else if build_with_helper {
        "[sp1] "
    } else if docker {
        "[docker] "
    } else {
        ""
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

/// Add the `cargo prove build` arguments to the `command_args` vec. This is useful when adding
/// the `cargo prove build` arguments to an existing command.
fn add_cargo_prove_build_args(
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
        // `cargo prove build` accepts a comma-separated list of features.
        let features = prove_args.features.join(",");
        command_args.push("--features".to_string());
        command_args.push(features);
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

/// Build a program with the specified BuildArgs. program_dir is specified as an argument when
/// the program is built via build_program in sp1-helper.
pub fn build_program(args: &BuildArgs, program_dir: Option<PathBuf>) -> Result<Utf8PathBuf> {
    let is_helper = program_dir.is_some();
    let program_dir = program_dir.unwrap_or_else(|| {
        // Get the current directory.
        std::env::current_dir().expect("Failed to get current directory.")
    });
    let program_dir: Utf8PathBuf = program_dir
        .try_into()
        .expect("Failed to convert PathBuf to Utf8PathBuf");

    let metadata_cmd = cargo_metadata::MetadataCommand::new();
    let metadata = metadata_cmd.exec().unwrap();
    let root_package = metadata.root_package();
    let root_package_name = root_package.as_ref().map(|p| &p.name);

    let build_target = "riscv32im-succinct-zkvm-elf".to_string();
    let mut cmd = if args.docker {
        let mut docker_cmd = Command::new("docker");
        get_docker_cmd(
            &mut docker_cmd,
            args,
            &metadata.workspace_root,
            &program_dir,
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

    let elf_path = metadata
        .target_directory
        .join(build_target.clone())
        .join("release")
        .join(root_package_name.unwrap());

    let elf_dir = program_dir.join("elf");
    fs::create_dir_all(&elf_dir)?;

    // The order of precedence for the ELF name is:
    // 1. --elf flag
    // 2. --binary flag (binary name + -elf suffix)
    // 3. default (root package name)
    let elf_name = if let Some(elf) = &args.elf {
        elf.to_string()
    } else if let Some(binary) = &args.binary {
        format!("{}-elf", binary)
    } else {
        root_package_name.unwrap().to_string()
    };
    let result_elf_path = elf_dir.join(elf_name);
    fs::copy(elf_path, &result_elf_path)?;

    Ok(result_elf_path)
}
