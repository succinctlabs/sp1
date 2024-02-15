use crate::CommandExecutor;
use anyhow::{Context, Result};
use cargo_metadata::camino::Utf8PathBuf;
use std::{
    fs,
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    thread,
};

pub fn build_program(docker: bool) -> Result<Utf8PathBuf> {
    let metadata_cmd = cargo_metadata::MetadataCommand::new();
    let metadata = metadata_cmd.exec().unwrap();
    let root_package = metadata.root_package();
    let root_package_name = root_package.as_ref().map(|p| &p.name);

    let build_target = "riscv32im-succinct-zkvm-elf";
    if docker {
        let mut child = Command::new("docker")
            .args([
                "run",
                "--rm",
                "-v",
                format!("{}:/root/program", metadata.workspace_root).as_str(),
                "sp1-build",
                "prove",
                "build",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to run docker.")?;

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
            return Err(anyhow::anyhow!("Failed to build program."));
        }
    } else {
        let rust_flags = [
            "-C",
            "passes=loweratomic",
            "-C",
            "link-arg=-Ttext=0x00200800",
            "-C",
            "panic=abort",
        ];

        Command::new("cargo")
            .env("RUSTUP_TOOLCHAIN", "succinct")
            .env("CARGO_ENCODED_RUSTFLAGS", rust_flags.join("\x1f"))
            .args(["build", "--release", "--target", build_target, "--locked"])
            .run()
            .context("Failed to run cargo command.")?;
    }

    let elf_path = metadata
        .target_directory
        .join(build_target)
        .join("release")
        .join(root_package_name.unwrap());
    let elf_dir = metadata.target_directory.parent().unwrap().join("elf");
    fs::create_dir_all(&elf_dir)?;
    let result_elf_path = elf_dir.join("riscv32im-succinct-zkvm-elf");
    fs::copy(elf_path, &result_elf_path)?;

    Ok(result_elf_path)
}
