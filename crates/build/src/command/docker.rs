use std::process::{exit, Command, Stdio};

use anyhow::{Context, Result};
use cargo_metadata::camino::Utf8PathBuf;

use crate::BuildArgs;

use super::utils::{get_program_build_args, get_rust_compiler_flags};

/// Uses SP1_DOCKER_IMAGE environment variable if set, otherwise constructs the image to use based
/// on the provided tag.
fn get_docker_image(tag: &str) -> String {
    std::env::var("SP1_DOCKER_IMAGE").unwrap_or_else(|_| {
        let image_base = "ghcr.io/succinctlabs/sp1";
        format!("{}:{}", image_base, tag)
    })
}

/// Creates a Docker command to build the program.
pub(crate) fn create_docker_command(
    args: &BuildArgs,
    program_dir: &Utf8PathBuf,
    program_metadata: &cargo_metadata::Metadata,
) -> Result<Command> {
    let image = get_docker_image(&args.tag);
    let canonicalized_program_dir: Utf8PathBuf = program_dir
        .canonicalize()
        .expect("Failed to canonicalize program directory")
        .try_into()
        .unwrap();

    let workspace_root: &Utf8PathBuf = &args
        .workspace_directory
        .as_deref()
        .map(|workspace_path| {
            std::path::Path::new(workspace_path)
                .to_path_buf()
                .canonicalize()
                .expect("Failed to canonicalize workspace directory")
                .try_into()
                .unwrap()
        })
        .unwrap_or_else(|| program_metadata.workspace_root.clone());

    // Ensure the workspace directory is parent of the program
    if !program_metadata.workspace_root.starts_with(workspace_root) {
        eprintln!(
            "Workspace root ({}) must be a parent of the program directory ({}).",
            workspace_root, program_metadata.workspace_root
        );
        exit(1);
    }

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

    // Mount the entire workspace, and set the working directory to the program dir. Note: If the
    // program dir has local dependencies outside of the workspace, building with Docker will fail.
    let workspace_root_path = format!("{}:/root/program", workspace_root);
    let program_dir_path = format!(
        "/root/program/{}",
        canonicalized_program_dir.strip_prefix(workspace_root).unwrap()
    );

    // Get the target directory for the ELF in the context of the Docker container.
    let relative_target_dir =
        (program_metadata.target_directory).strip_prefix(workspace_root).unwrap();
    let target_dir = format!(
        "/root/program/{}/{}/{}",
        relative_target_dir,
        crate::HELPER_TARGET_SUBDIR,
        "docker"
    );

    let parsed_version = {
        let output = Command::new("docker")
            .args([
                "run",
                "--rm",
                "--platform",
                "linux/amd64",
                "-e",
                &format!("RUSTUP_TOOLCHAIN={}", super::TOOLCHAIN_NAME),
                "--entrypoint",
                "",
                "-i",
                &image,
                "rustc",
                "--version",
            ])
            .output()
            .expect("rustc --version should succeed in docker image");

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Failed to run rustc --version in docker image {}",
                String::from_utf8_lossy(&output.stdout)
            ));
        }

        let stdout_string =
            String::from_utf8(output.stdout).expect("Can't parse rustc --version stdout");

        println!("cargo:warning=docker: rustc +succinct --version: {:?}", stdout_string);

        super::utils::parse_rustc_version(&stdout_string)
    };

    // When executing the Docker command:
    // 1. Set the target directory to a subdirectory of the program's target directory to avoid
    //    build
    // conflicts with the parent process. Source: https://github.com/rust-lang/cargo/issues/6412
    // 2. Set the rustup toolchain to succinct.
    // 3. Set the encoded rust flags.
    // Note: In Docker, you can't use the .env command to set environment variables, you have to use
    // the -e flag.
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
        format!("CARGO_TARGET_DIR={}", target_dir),
        "-e".to_string(),
        format!("RUSTUP_TOOLCHAIN={}", super::TOOLCHAIN_NAME),
        // TODO: remove once trim-paths is supported - https://github.com/rust-lang/rust/issues/111540
        "-e".to_string(),
        "RUSTC_BOOTSTRAP=1".to_string(), // allows trim-paths.
        "-e".to_string(),
        format!("CARGO_ENCODED_RUSTFLAGS={}", get_rust_compiler_flags(args, &parsed_version)),
        "--entrypoint".to_string(),
        "".to_string(),
        image,
        "cargo".to_string(),
    ];

    // Add the SP1 program build arguments.
    docker_args.extend_from_slice(&get_program_build_args(args));

    let mut command = Command::new("docker");
    command.current_dir(canonicalized_program_dir.clone()).args(&docker_args);
    Ok(command)
}
