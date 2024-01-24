use std::process::{Command, Stdio};

use anyhow::Result;
use clap::Parser;

const RUSTUP_TOOLCHAIN_NAME: &str = "succinct";

#[derive(Parser)]
#[command(name = "build-toolchain", about = "Build the cargo-prove toolchain.")]
pub struct BuildToolchainCmd {}

impl BuildToolchainCmd {
    pub fn run(&self) -> Result<()> {
        // Get enviroment variables.
        let github_access_token = std::env::var("GITHUB_ACCESS_TOKEN");

        // Clone our rust fork.
        let repo_url = match github_access_token {
            Ok(github_access_token) => format!(
                "https://{}@github.com/succinctlabs/rust",
                github_access_token
            ),
            Err(_) => "https://github.com/succinctlabs/rust".to_string(),
        };
        Command::new("git")
            .args(["clone", &repo_url])
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
            .env(
                "CARGO_TARGET_RISCV32IM_SUCCINCT_ZKVM_ELF_RUSTFLAGS",
                "-Cpasses=loweratomic",
            )
            .args(["x.py", "build"])
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .current_dir("rust")
            .output()?;

        // Build the toolchain (stage 2).
        Command::new("python3")
            .env(
                "CARGO_TARGET_RISCV32IM_SUCCINCT_ZKVM_ELF_RUSTFLAGS",
                "-Cpasses=loweratomic",
            )
            .args(["x.py", "build", "--stage", "2"])
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .current_dir("rust")
            .output()?;

        // Remove the existing toolchain from rustup, if it exists.
        match Command::new("rustup")
            .args(["toolchain", "remove", RUSTUP_TOOLCHAIN_NAME])
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()
        {
            Ok(_) => println!("Succesfully removed existing toolchain."),
            Err(_) => println!("No existing toolchain to remove."),
        }

        // Find the toolchain directory.
        let mut toolchain_dir = None;
        for wentry in std::fs::read_dir("rust/build")? {
            let entry = wentry?;
            let toolchain_dir_candidate = entry.path().join("stage2");
            if toolchain_dir_candidate.is_dir() {
                toolchain_dir = Some(toolchain_dir_candidate);
                break;
            }
        }
        let toolchain_dir = toolchain_dir.unwrap();
        println!(
            "Found toolchain directory at {}",
            toolchain_dir.as_path().to_str().unwrap()
        );

        // Link the toolchain to rustup.
        Command::new("rustup")
            .args(["toolchain", "link", RUSTUP_TOOLCHAIN_NAME])
            .arg(toolchain_dir)
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()?;

        Ok(())
    }
}
