use anyhow::{Context, Result};
// use cargo_metadata::camino::Utf8PathBuf;
// use clap::Parser;
use std::{
    io::{BufRead, BufReader},
    process::{exit, Command, Stdio},
    thread,
};

fn call_container() -> Result<()> {
    let image_name = "sp1-recursion-gnark-ffi";

    let docker_check = Command::new("docker")
        .args(["info"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("failed to run docker command")?;

    if !docker_check.success() {
        eprintln!("Docker is not installed or not running.");
        exit(1);
    }

    let mut child = Command::new("docker")
        .args(["run", "--rm", image_name, "arbitrary", "arguments"])
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

    Ok(())
}
