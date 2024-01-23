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

        // Install our config.toml.
        let config_toml = include_str!("config.toml");
        std::fs::write("rust/config.toml", config_toml)?;

        // Build the toolchain (stage 1).
        Command::new("python3")
            .args(["x.py", "build"])
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()?;

        // Build the toolchain (stage 2).
        Command::new("python3")
            .args(["x.py", "build", "--stage", "2"])
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()?;

        // Link the toolchain to rustup.
        Command::new("rustup")
            .args(["toolchain", "link", "riscv32im-succinct-zkvm-elf", "."])
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()?;

        Ok(())
    }
}
