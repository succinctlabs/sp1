#[cfg(feature = "clap")]
use clap::Parser;
use std::{
    fs,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{exit, Command, Stdio},
    thread,
};

use anyhow::{Context, Result};
use cargo_metadata::camino::Utf8PathBuf;

#[derive(Default, Clone)]
// `clap` is enabled in the `cli` crate for `sp1-helper`, when users are building programs with
// `cargo prove` CLI directly. The `helper` crate is intended to be lightweight, so we only derive
// the `Parser` trait if the `clap` feature is enabled.
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

// TODO: Pipe the output to SP1 if done via build_program. Either should be an argument or return the Command itself.

/// Build a program with the specified BuildArgs.
pub fn build_program(args: &BuildArgs, program_dir: Option<PathBuf>) -> Result<Utf8PathBuf> {
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
    if args.docker {
        let image = get_docker_image(&args.tag);

        let docker_check = Command::new("docker")
            .args(["info"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("failed to run docker command")?;

        if !docker_check.success() {
            eprintln!(
                "docker is not installed or not running: https://docs.docker.com/get-docker/"
            );
            exit(1);
        }

        let workspace_root_path = format!("{}:/root/program", metadata.workspace_root);
        let mut child_args = vec![
            "run".to_string(),
            "--rm".to_string(),
            "--platform".to_string(),
            "linux/amd64".to_string(),
            "-v".to_string(),
            workspace_root_path,
            image,
            "prove".to_string(),
            "build".to_string(),
        ];

        // Add the `cargo prove build` arguments to the child process command, while ignoring
        // `--docker`, as this command will be invoked in a docker container.
        add_cargo_prove_build_args(&mut child_args, args.clone(), true);

        let mut child = Command::new("docker")
            .args(&child_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to spawn command")?;

        let stdout = BufReader::new(child.stdout.take().unwrap());
        let stderr = BufReader::new(child.stderr.take().unwrap());

        // Pipe stdout and stderr to the parent process with [docker] prefix
        let stdout_handle = thread::spawn(move || {
            stdout.lines().for_each(|line| {
                println!("[docker] {}", line.unwrap());
            });
        });
        stderr.lines().for_each(|line| {
            eprintln!("[docker] {}", line.unwrap());
        });

        stdout_handle.join().unwrap();

        let result = child.wait()?;
        if !result.success() {
            // Error message is already printed by cargo
            exit(result.code().unwrap_or(1))
        }
    } else {
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
            build_target.clone(),
        ];

        // Add the `cargo prove build` arguments to the child process command, while ignoring
        // `--docker`, as we already know it's unused in this conditional.
        add_cargo_prove_build_args(&mut cargo_args, args.clone(), true);

        // Ensure the Cargo.lock doesn't update.
        cargo_args.push("--locked".to_string());

        let result = Command::new("cargo")
            .current_dir(program_dir.clone())
            .env("RUSTUP_TOOLCHAIN", "succinct")
            .env("CARGO_ENCODED_RUSTFLAGS", rust_flags.join("\x1f"))
            .args(&cargo_args)
            .status()
            .context("Failed to run cargo command.")?;

        if !result.success() {
            exit(result.code().unwrap_or(1))
        }
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
    // 3. default (build target: riscv32im-succinct-zkvm-elf)
    let elf_name = if let Some(elf) = &args.elf {
        elf.to_string()
    } else if let Some(binary) = &args.binary {
        format!("{}-elf", binary)
    } else {
        build_target
    };
    let result_elf_path = elf_dir.join(elf_name);
    fs::copy(elf_path, &result_elf_path)?;

    Ok(result_elf_path)
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
