mod docker;

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

const BUILD_TARGET: &str = "riscv32im-succinct-zkvm-elf";
const DEFAULT_TAG: &str = "latest";
const DEFAULT_OUTPUT_DIR: &str = "elf";
const HELPER_TARGET_SUBDIR: &str = "elf-compilation";

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

/// Get the arguments to build the program with the arguments from the [`BuildArgs`] struct.
fn get_program_build_args(args: &BuildArgs) -> Vec<String> {
    let mut build_args = vec![
        "build".to_string(),
        "--release".to_string(),
        "--target".to_string(),
        BUILD_TARGET.to_string(),
    ];

    if args.ignore_rust_version {
        build_args.push("--ignore-rust-version".to_string());
    }

    if !args.binary.is_empty() {
        build_args.push("--bin".to_string());
        build_args.push(args.binary.clone());
    }

    if !args.features.is_empty() {
        build_args.push("--features".to_string());
        build_args.push(args.features.join(","));
    }

    if args.no_default_features {
        build_args.push("--no-default-features".to_string());
    }

    if args.locked {
        build_args.push("--locked".to_string());
    }

    build_args
}

/// Rust flags for compilation of C libraries.
fn get_rust_compiler_flags() -> String {
    let rust_flags = [
        "-C".to_string(),
        "passes=loweratomic".to_string(),
        "-C".to_string(),
        "link-arg=-Ttext=0x00200800".to_string(),
        "-C".to_string(),
        "panic=abort".to_string(),
    ];
    rust_flags.join("\x1f")
}

/// Get the command to build the program locally.
fn create_local_command(args: &BuildArgs, program_dir: &Utf8PathBuf) -> Command {
    let mut command = Command::new("cargo");
    let canonicalized_program_dir = program_dir
        .canonicalize()
        .expect("Failed to canonicalize program directory");

    // Check if CC_riscv32im_succinct_zkvm_elf is set, if not, set it to the downloaded toolchain
    if std::env::var("CC_riscv32im_succinct_zkvm_elf").is_err() {
        let home_dir = std::env::var("HOME").expect("HOME environment variable is not set");
        let cc_path = format!(
            "{}/.config/.sp1/riscv/riscv32im-osx-arm64/bin/riscv32-unknown-elf-gcc",
            home_dir
        );
        command.env("CC_riscv32im_succinct_zkvm_elf", cc_path);
    }

    command
        .current_dir(canonicalized_program_dir)
        .env("RUSTUP_TOOLCHAIN", "succinct")
        .env("CARGO_ENCODED_RUSTFLAGS", get_rust_compiler_flags())
        .args(&get_program_build_args(args));
    command
}

/// Execute the command and handle the output depending on the context.
fn execute_command(
    mut command: Command,
    docker: bool,
    program_metadata: &cargo_metadata::Metadata,
) -> Result<()> {
    // Strip the rustc configuration, otherwise in the helper it will attempt to compile the SP1
    // program with the toolchain of the normal build process, rather than the Succinct toolchain.
    command.env_remove("RUSTC");

    // Set the target directory to a subdirectory of the program's target directory to avoid
    // build conflicts with the parent process. If removed, programs that share the same target
    // directory (i.e. same workspace) as the script will hang indefinitely due to a file lock
    // when building in the helper.
    // Source: https://github.com/rust-lang/cargo/issues/6412
    command.env(
        "CARGO_TARGET_DIR",
        program_metadata.target_directory.join(HELPER_TARGET_SUBDIR),
    );

    // Add necessary tags for stdout and stderr from the command.
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn command")?;
    let stdout = BufReader::new(child.stdout.take().unwrap());
    let stderr = BufReader::new(child.stderr.take().unwrap());

    // Add prefix to the output of the process depending on the context.
    let msg = match docker {
        true => "[sp1] [docker] ",
        false => "[sp1] ",
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

    // Wait for the child process to finish and check the result.
    let result = child.wait()?;
    if !result.success() {
        // Error message is already printed by cargo.
        exit(result.code().unwrap_or(1))
    }
    Ok(())
}

/// Copy the ELF to the specified output directory.
fn copy_elf_to_output_dir(
    args: &BuildArgs,
    program_metadata: &cargo_metadata::Metadata,
) -> Result<Utf8PathBuf> {
    let root_package = program_metadata.root_package();
    let root_package_name = root_package.as_ref().map(|p| &p.name);

    // The ELF is written to a target folder specified by the program's package.
    let original_elf_path = program_metadata
        .target_directory
        .join(HELPER_TARGET_SUBDIR)
        .join(BUILD_TARGET)
        .join("release")
        .join(root_package_name.unwrap());

    // The order of precedence for the ELF name is:
    // 1. --elf_name flag
    // 2. --binary flag + -elf suffix (defaults to riscv32im-succinct-zkvm-elf)
    let elf_name = if !args.elf_name.is_empty() {
        args.elf_name.clone()
    } else if !args.binary.is_empty() {
        // TODO: In the future, change this to default to the package name. Will require updating
        // docs and examples.
        args.binary.clone()
    } else {
        BUILD_TARGET.to_string()
    };

    let elf_dir = program_metadata
        .target_directory
        .parent()
        .unwrap()
        .join(&args.output_directory);
    fs::create_dir_all(&elf_dir)?;
    let result_elf_path = elf_dir.join(elf_name);

    // Copy the ELF to the specified output directory.
    fs::copy(original_elf_path, &result_elf_path)?;

    Ok(result_elf_path)
}

/// Build a program with the specified [`BuildArgs`]. The `program_dir` is specified as an argument when
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
    // If the program directory is not specified, use the current directory.
    let program_dir = program_dir
        .unwrap_or_else(|| std::env::current_dir().expect("Failed to get current directory."));
    let program_dir: Utf8PathBuf = program_dir
        .try_into()
        .expect("Failed to convert PathBuf to Utf8PathBuf");

    // The root package name corresponds to the package name of the current directory.
    let metadata_cmd = cargo_metadata::MetadataCommand::new();
    let metadata = metadata_cmd.exec().unwrap();

    // Get the command corresponding to Docker or local build.
    let cmd = if args.docker {
        docker::create_docker_command(args, &program_dir, &metadata.workspace_root)?
    } else {
        create_local_command(args, &program_dir)
    };

    let program_metadata_file = program_dir.join("Cargo.toml");
    let mut program_metadata_cmd = cargo_metadata::MetadataCommand::new();
    let program_metadata = program_metadata_cmd
        .manifest_path(program_metadata_file)
        .exec()
        .unwrap();

    execute_command(cmd, args.docker, &program_metadata)?;

    copy_elf_to_output_dir(args, &program_metadata)
}
