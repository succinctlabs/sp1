use anyhow::{Context, Result};
use clap::Parser;
use std::{path::PathBuf, process::Command};

use crate::{get_target, CommandExecutor, RUSTUP_TOOLCHAIN_NAME};

const RUST_REPO_NAME: &str = "sp1-rust";
const RUST_BRANCH: &str = "succinct";
const CONFIG_FILE_NAME: &str = "config.toml";
const TARGET_JSON: &str = "riscv32im-succinct-zkvm-elf.json";
const RUSTFLAGS: &str = "-Cpasses=loweratomic";

/// Command for building the cargo-prove toolchain
#[derive(Parser, Debug)]
#[command(name = "build-toolchain", about = "Build the cargo-prove toolchain.")]
pub struct BuildToolchainCmd {}

impl BuildToolchainCmd {
    /// Clones the Rust repository if necessary
    fn clone_rust_repo(github_token: Option<String>, temp_dir: &PathBuf) -> Result<PathBuf> {
        let dir = temp_dir.join(RUST_REPO_NAME);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }

        println!("No SP1_BUILD_DIR detected, cloning rust.");
        let repo_url = match github_token {
            Some(token) => {
                println!("Detected GITHUB_ACCESS_TOKEN, using it to clone rust.");
                format!("https://{}@github.com/succinctlabs/rust", token)
            }
            None => {
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
                &format!("--branch={}", RUST_BRANCH),
                RUST_REPO_NAME,
            ])
            .current_dir(temp_dir)
            .run()
            .context("Failed to clone repository")?;

        Self::setup_git_repo(&dir)?;
        Ok(dir)
    }

    /// Sets up the git repository with submodules
    fn setup_git_repo(dir: &PathBuf) -> Result<()> {
        Command::new("git")
            .args(["reset", "--hard"])
            .current_dir(dir)
            .run()
            .context("Failed to reset git repository")?;

        Command::new("git")
            .args(["submodule", "update", "--init", "--recursive", "--progress"])
            .current_dir(dir)
            .run()
            .context("Failed to update git submodules")?;

        Ok(())
    }

    /// Builds the Rust toolchain
    fn build_toolchain(rust_dir: &PathBuf, temp_dir: &PathBuf) -> Result<()> {
        let build_cmd = |stage: Option<&str>| {
            let mut args = vec!["x.py", "build"];
            if let Some(stage) = stage {
                args.extend(["--stage", stage]);
            }

            Command::new("python3")
                .env("RUST_TARGET_PATH", temp_dir)
                .env("CARGO_TARGET_RISCV32IM_SUCCINCT_ZKVM_ELF_RUSTFLAGS", RUSTFLAGS)
                .args(args)
                .current_dir(rust_dir)
                .run()
        };

        build_cmd(None).context("Failed to build stage 1")?;
        build_cmd(Some("2")).context("Failed to build stage 2")?;

        Ok(())
    }

    /// Executes the build toolchain command
    pub fn run(&self) -> Result<()> {
        let github_token = std::env::var("GITHUB_ACCESS_TOKEN").ok();
        let build_dir = std::env::var("SP1_BUILD_DIR").ok();

        let rust_dir = match build_dir {
            Some(dir) => {
                println!("Detected SP1_BUILD_DIR, skipping cloning rust.");
                PathBuf::from(dir).join("rust")
            }
            None => {
                let temp_dir = std::env::temp_dir();
                Self::clone_rust_repo(github_token, &temp_dir)?
            }
        };

        // Setup configuration and target
        let config_toml = include_str!("config.toml");
        let config_file = rust_dir.join(CONFIG_FILE_NAME);
        std::fs::write(&config_file, config_toml)
            .with_context(|| format!("Failed to write configuration to {:?}", config_file))?;

        let temp_dir = std::env::temp_dir().join("rustc-targets");
        std::fs::create_dir_all(&temp_dir)?;
        std::fs::File::create(temp_dir.join(TARGET_JSON))?;

        // Build toolchain
        Self::build_toolchain(&rust_dir, &temp_dir)?;

        // Handle toolchain installation
        if let Err(_) = Command::new("rustup")
            .args(["toolchain", "remove", RUSTUP_TOOLCHAIN_NAME])
            .run()
        {
            println!("No existing toolchain to remove.");
        }

        // Find and setup toolchain directory
        let toolchain_dir = std::fs::read_dir(rust_dir.join("build"))?
            .filter_map(Result::ok)
            .find_map(|entry| {
                let dir = entry.path().join("stage2");
                if dir.is_dir() {
                    Some(dir)
                } else {
                    None
                }
            })
            .context("Failed to find toolchain directory")?;

        // Setup binaries and link toolchain
        Self::setup_toolchain_binaries(&toolchain_dir)?;
        
        // Create compressed archive
        Self::create_toolchain_archive(&toolchain_dir)?;

        Ok(())
    }

    /// Sets up the toolchain binaries
    fn setup_toolchain_binaries(toolchain_dir: &PathBuf) -> Result<()> {
        let tools_bin_dir = toolchain_dir.parent().unwrap().join("stage2-tools-bin");
        let target_bin_dir = toolchain_dir.join("bin");

        for tool in tools_bin_dir.read_dir()? {
            let tool = tool?;
            let tool_name = tool.file_name();
            std::fs::copy(tool.path(), target_bin_dir.join(tool_name))?;
        }

        Command::new("rustup")
            .args(["toolchain", "link", RUSTUP_TOOLCHAIN_NAME])
            .arg(toolchain_dir)
            .run()
            .context("Failed to link toolchain to rustup")?;

        println!("Successfully linked the toolchain to rustup.");
        Ok(())
    }

    /// Creates a compressed archive of the toolchain
    fn create_toolchain_archive(toolchain_dir: &PathBuf) -> Result<()> {
        let target = get_target();
        let tar_gz_path = format!("rust-toolchain-{}.tar.gz", target);
        
        Command::new("tar")
            .args([
                "--exclude", "lib/rustlib/src",
                "--exclude", "lib/rustlib/rustc-src",
                "-hczvf", &tar_gz_path,
                "-C", toolchain_dir.to_str().unwrap(),
                ".",
            ])
            .run()
            .context("Failed to create toolchain archive")?;

        println!("Successfully compressed the toolchain to {}.", tar_gz_path);
        Ok(())
    }
}
