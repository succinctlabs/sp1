use std::process::{Command, Stdio};

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(name = "build-toolchain", about = "Build the cargo-prove toolchain.")]
pub struct BuildToolChainCmd {}

impl BuildToolChainCmd {
    pub fn run(&self) -> Result<()> {
        // Clone our rust fork.
        Command::new("git")
            .args(["clone", "https://github.com/succinctlabs/rust.git"])
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()?;

        // Checkout the correct branch.
        Command::new("git")
            .args(["checkout", "succinct"])
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .current_dir("rust")
            .output()?;

        // Install our config.toml.
        let config_toml = include_str!("config.toml");
        std::fs::write("rust/config.toml", config_toml)?;

        // Build the toolchain (stage 1).
        Command::new("python3")
            .args(["x.py", "build"])
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .current_dir("rust")
            .output()?;

        // Build the toolchain (stage 2).
        Command::new("python3")
            .args(["x.py", "build", "--stage", "2"])
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .current_dir("rust")
            .output()?;

        // Remove the existing toolchain from rustup, if it exists.
        match Command::new("rustup")
            .args(["toolchain", "remove", "riscv32im-succinct-zkvm-elf"])
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()
        {
            Ok(_) => println!("Succesfully removed existing toolchain."),
            Err(_) => println!("No existing toolchain to remove."),
        }

        let mut toolchain_dir = None;
        for wentry in std::fs::read_dir("rust/build")? {
            let entry = wentry?;
            let toolchain_dir_candidate = entry.path().join("stage2");
            if toolchain_dir_candidate.is_dir() {
                toolchain_dir = Some(toolchain_dir_candidate);
                break;
            }
        }

        // Link the toolchain to rustup.
        Command::new("rustup")
            .args(["toolchain", "link", "riscv32im-succinct-zkvm-elf"])
            .arg(toolchain_dir.unwrap())
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()?;

        Ok(())
    }
}
