use anyhow::Context;
use chrono::Local;
use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    thread,
};

fn current_datetime() -> String {
    let now = Local::now();
    now.format("%Y-%m-%d %H:%M:%S").to_string()
}

pub use anyhow::Error as BuildError;

pub fn build_program(path: &str) -> Result<(), BuildError> {
    let program_dir = std::path::Path::new(path);

    // Tell cargo to rerun the script only if program/{src, Cargo.toml, Cargo.lock} changes
    // Ref: https://doc.rust-lang.org/nightly/cargo/reference/build-scripts.html#rerun-if-changed
    let dirs = vec![
        program_dir.join("src"),
        program_dir.join("Cargo.toml"),
        program_dir.join("Cargo.lock"),
    ];
    for dir in dirs {
        println!("cargo:rerun-if-changed={}", dir.display());
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

    let err = anyhow::anyhow!(
        "Failed to build the program located in `{}`.",
        program_dir.display(),
    );
    match execute_build_cmd(&program_dir) {
        Ok(status) => {
            if !status.success() {
                return Err(err).with_context(|| {
                    format!("Build process returned non-zero exit code {}", status)
                });
            }
        }
        Err(e) => {
            return Err(err.context(e));
        }
    }
    Ok(())
}

/// Executes the `cargo prove build` command in the program directory
fn execute_build_cmd(
    program_dir: &impl AsRef<std::path::Path>,
) -> Result<std::process::ExitStatus, std::io::Error> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(program_dir)
        .args(["prove", "build"])
        .env("CARGO_MANIFEST_DIR", program_dir.as_ref())
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
