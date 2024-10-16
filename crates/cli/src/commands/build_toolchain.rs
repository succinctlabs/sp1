use anyhow::{Context, Result};
use clap::Parser;
use std::{path::PathBuf, process::Command};

use crate::{get_target, CommandExecutor, RUSTUP_TOOLCHAIN_NAME};

#[derive(Parser)]
#[command(name = "build-toolchain", about = "Build the cargo-prove toolchain.")]
pub struct BuildToolchainCmd {}

impl BuildToolchainCmd {
    pub fn run(&self) -> Result<()> {
        // Get environment variables.
        let github_access_token = std::env::var("GITHUB_ACCESS_TOKEN");
        let build_dir = std::env::var("SP1_BUILD_DIR");

        // Clone our rust fork, if necessary.
        let rust_dir = match build_dir {
            Ok(build_dir) => {
                println!("Detected SP1_BUILD_DIR, skipping cloning rust.");
                PathBuf::from(build_dir).join("rust")
            }
            Err(_) => {
                let temp_dir = std::env::temp_dir();
                let dir = temp_dir.join("sp1-rust");
                if dir.exists() {
                    std::fs::remove_dir_all(&dir)?;
                }

                println!("No SP1_BUILD_DIR detected, cloning rust.");
                let repo_url = match github_access_token {
                    Ok(github_access_token) => {
                        println!("Detected GITHUB_ACCESS_TOKEN, using it to clone rust.");
                        format!("https://{}@github.com/succinctlabs/rust", github_access_token)
                    }
                    Err(_) => {
                        println!("No GITHUB_ACCESS_TOKEN detected. If you get throttled by Github, set it to bypass the rate limit.");
                        "ssh://git@github.com/succinctlabs/rust".to_string()
                    }
                };
                Command::new("git")
                    .args([
                        "clone",
                        &repo_url,
                        "--depth=1",
                        "--single-branch",
                        "--branch=succinct",
                        "sp1-rust",
                    ])
                    .current_dir(&temp_dir)
                    .run()?;
                Command::new("git").args(["reset", "--hard"]).current_dir(&dir).run()?;
                Command::new("git")
                    .args(["submodule", "update", "--init", "--recursive", "--progress"])
                    .current_dir(&dir)
                    .run()?;
                dir
            }
        };

        // Install our config.toml.
        let config_toml = include_str!("config.toml");
        let config_file = rust_dir.join("config.toml");
        std::fs::write(&config_file, config_toml)
            .with_context(|| format!("while writing configuration to {:?}", config_file))?;

        // Work around target sanity check added in rust-lang/rust@09c076810cb7649e5817f316215010d49e78e8d7.
        let temp_dir = std::env::temp_dir().join("rustc-targets");
        if !temp_dir.exists() {
            std::fs::create_dir_all(&temp_dir)?;
        }
        std::fs::File::create(temp_dir.join("riscv32im-succinct-zkvm-elf.json"))?;

        // Build the toolchain (stage 1).
        Command::new("python3")
            .env("RUST_TARGET_PATH", &temp_dir)
            .env("CARGO_TARGET_RISCV32IM_SUCCINCT_ZKVM_ELF_RUSTFLAGS", "-Cpasses=loweratomic")
            .args(["x.py", "build"])
            .current_dir(&rust_dir)
            .run()?;

        // Build the toolchain (stage 2).
        Command::new("python3")
            .env("RUST_TARGET_PATH", &temp_dir)
            .env("CARGO_TARGET_RISCV32IM_SUCCINCT_ZKVM_ELF_RUSTFLAGS", "-Cpasses=loweratomic")
            .args(["x.py", "build", "--stage", "2"])
            .current_dir(&rust_dir)
            .run()?;

        // Remove the existing toolchain from rustup, if it exists.
        match Command::new("rustup").args(["toolchain", "remove", RUSTUP_TOOLCHAIN_NAME]).run() {
            Ok(_) => println!("Successfully removed existing toolchain."),
            Err(_) => println!("No existing toolchain to remove."),
        }

        // Find the toolchain directory.
        let mut toolchain_dir = None;
        for wentry in std::fs::read_dir(rust_dir.join("build"))? {
            let entry = wentry?;
            let toolchain_dir_candidate = entry.path().join("stage2");
            if toolchain_dir_candidate.is_dir() {
                toolchain_dir = Some(toolchain_dir_candidate);
                break;
            }
        }
        let toolchain_dir = toolchain_dir.unwrap();
        println!(
            "Found built toolchain directory at {}.",
            toolchain_dir.as_path().to_str().unwrap()
        );

        // Copy over the stage2-tools-bin directory to the toolchain bin directory.
        let tools_bin_dir = toolchain_dir.parent().unwrap().join("stage2-tools-bin");
        let target_bin_dir = toolchain_dir.join("bin");
        for tool in tools_bin_dir.read_dir()? {
            let tool = tool?;
            let tool_name = tool.file_name();
            std::fs::copy(tool.path(), target_bin_dir.join(tool_name))?;
        }

        // Link the toolchain to rustup.
        Command::new("rustup")
            .args(["toolchain", "link", RUSTUP_TOOLCHAIN_NAME])
            .arg(&toolchain_dir)
            .run()?;
        println!("Successfully linked the toolchain to rustup.");

        // Compressing toolchain directory to tar.gz.
        let target = get_target();
        let tar_gz_path = format!("rust-toolchain-{}.tar.gz", target);
        Command::new("tar")
            .args([
                "--exclude",
                "lib/rustlib/src",
                "--exclude",
                "lib/rustlib/rustc-src",
                "-hczvf",
                &tar_gz_path,
                "-C",
                toolchain_dir.to_str().unwrap(),
                ".",
            ])
            .run()?;
        println!("Successfully compressed the toolchain to {}.", tar_gz_path);

        Ok(())
    }
}
