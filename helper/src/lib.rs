use chrono::Local;
use clap::Parser;
use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    thread,
};

#[derive(Parser, Default)]
pub struct BuildArgs {
    #[clap(long, action, help = "Build using Docker for reproducible builds.")]
    pub docker: bool,
    #[clap(long, action, help = "Ignore Rust version check.")]
    pub ignore_rust_version: bool,
    #[clap(long, action, help = "If building a binary, specify the name.")]
    pub binary: Option<String>,
    #[clap(long, action, help = "ELF binary name.")]
    pub elf: Option<String>,
    #[clap(long, action, help = "Build with features.")]
    pub features: Vec<String>,
}

fn current_datetime() -> String {
    let now = Local::now();
    now.format("%Y-%m-%d %H:%M:%S").to_string()
}

pub fn build_program(path: &str, args: Option<BuildArgs>) {
    println!("path: {:?}", path);
    let program_dir = std::path::Path::new(path);

    // Tell cargo to rerun the script only if program/{src, Cargo.toml, Cargo.lock} changes
    // Ref: https://doc.rust-lang.org/nightly/cargo/reference/build-scripts.html#rerun-if-changed
    let dirs = vec![
        program_dir.join("src"),
        program_dir.join("Cargo.toml"),
        program_dir.join("Cargo.lock"),
    ];
    for dir in dirs {
        println!("cargo::rerun-if-changed={}", dir.display());
    }

    // Print a message so the user knows that their program was built. Cargo caches warnings emitted
    // from build scripts, so we'll print the date/time when the program was built.
    let metadata_file = program_dir.join("Cargo.toml");
    let mut metadata_cmd = cargo_metadata::MetadataCommand::new();
    let metadata = metadata_cmd.manifest_path(metadata_file).exec().unwrap();
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

    let status = execute_build_cmd(&program_dir, args)
        .unwrap_or_else(|_| panic!("Failed to build `{}`.", root_package_name));
    if !status.success() {
        panic!("Failed to build `{}`.", root_package_name);
    }
}

/// Executes the `cargo prove build` command in the program directory
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

    let mut cargo_prove_build_args = vec!["prove".to_string(), "build".to_string()];
    if let Some(args) = args {
        if args.docker {
            cargo_prove_build_args.push("--docker".to_string());
        }
        if args.ignore_rust_version {
            cargo_prove_build_args.push("--ignore-rust-version".to_string());
        }
        if !args.features.is_empty() {
            for feature in args.features {
                cargo_prove_build_args.push("--features".to_string());
                cargo_prove_build_args.push(feature);
            }
        }
        if let Some(binary) = &args.binary {
            cargo_prove_build_args.push("--binary".to_string());
            cargo_prove_build_args.push(binary.clone());
        }
        if let Some(elf) = &args.elf {
            cargo_prove_build_args.push("--elf".to_string());
            cargo_prove_build_args.push(elf.clone());
        }
    }

    let mut cmd = Command::new("cargo");
    cmd.current_dir(program_dir)
        .args(cargo_prove_build_args)
        .env_remove("RUSTC")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn()?;

    let stdout = BufReader::new(child.stdout.take().unwrap());
    let stderr = BufReader::new(child.stderr.take().unwrap());

    // Pipe stdout and stderr to the parent process with [sp1] prefix
    let stdout_handle = thread::spawn(move || {
        stdout.lines().for_each(|line| {
            println!("[sp1] {}", line.unwrap());
        });
    });
    stderr.lines().for_each(|line| {
        eprintln!("[sp1] {}", line.unwrap());
    });

    stdout_handle.join().unwrap();

    child.wait()
}
