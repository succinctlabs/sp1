use anyhow::{Context, Result};
use cargo_metadata::semver;
use std::{
    io::{BufRead, BufReader},
    process::{exit, Command, Stdio},
    thread,
};

use crate::{BuildArgs, BUILD_TARGET};

/// Get the arguments to build the program with the arguments from the [`BuildArgs`] struct.
pub(crate) fn get_program_build_args(args: &BuildArgs) -> Vec<String> {
    let mut build_args = vec![
        "build".to_string(),
        "--release".to_string(),
        "--target".to_string(),
        BUILD_TARGET.to_string(),
    ];

    if args.ignore_rust_version {
        build_args.push("--ignore-rust-version".to_string());
    }

    build_args.push("-Ztrim-paths".to_string());

    for p in &args.packages {
        build_args.push("-p".to_string());
        build_args.push(p.to_string());
    }

    for b in &args.binaries {
        build_args.push("--bin".to_string());
        build_args.push(b.to_string());
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
pub(crate) fn get_rust_compiler_flags(args: &BuildArgs, version: &semver::Version) -> String {
    // Note: as of 1.81.0, the `-C passes=loweratomic` flag is deprecated, because of a change to
    // llvm.
    let atomic_lower_pass = if version > &semver::Version::new(1, 81, 0) {
        "passes=lower-atomic"
    } else {
        "passes=loweratomic"
    };

    let rust_flags = [
        "-C",
        atomic_lower_pass,
        "-C",
        "link-arg=-Ttext=0x00201000",
        "-C",
        "link-arg=--image-base=0x00200800",
        "-C",
        "panic=abort",
        "--cfg",
        "getrandom_backend=\"custom\"",
        "-C",
        "llvm-args=-misched-prera-direction=bottomup",
        "-C",
        "llvm-args=-misched-postra-direction=bottomup",
    ];
    let rust_flags: Vec<_> =
        rust_flags.into_iter().chain(args.rustflags.iter().map(String::as_str)).collect();
    rust_flags.join("\x1f")
}

/// Execute the command and handle the output depending on the context.
pub(crate) fn execute_command(mut command: Command, docker: bool) -> Result<()> {
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

pub(crate) fn parse_rustc_version(version: &str) -> semver::Version {
    let version_string =
        version.split(" ").nth(1).expect("Can't parse rustc --version stdout").trim();

    semver::Version::parse(version_string).expect("Can't parse rustc --version stdout")
}
