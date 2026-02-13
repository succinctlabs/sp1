use anyhow::{Context, Result};
use clap::Parser;
use std::{
    path::PathBuf,
    process::{Command, Stdio},
};

use crate::{get_target, LATEST_SUPPORTED_TOOLCHAIN_VERSION_TAG, RUSTUP_TOOLCHAIN_NAME};

// There is a lot of Commands in this module, having this trait back can
// help us simplify the code a bit.
trait CommandExecutor {
    fn run(&mut self) -> Result<()>;
}

impl CommandExecutor for Command {
    fn run(&mut self) -> Result<()> {
        self.stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()
            .with_context(|| format!("while executing `{:?}`", &self))
            .map(|_| ())
    }
}

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
                        format!("https://{github_access_token}@github.com/succinctlabs/rust")
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
                        &format!("--branch={LATEST_SUPPORTED_TOOLCHAIN_VERSION_TAG}"),
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

        // Install our bootstrap.toml.
        let bootstrap_toml = include_str!("bootstrap.toml");
        let bootstrap_file = rust_dir.join("bootstrap.toml");
        std::fs::write(&bootstrap_file, bootstrap_toml)
            .with_context(|| format!("while writing configuration to {bootstrap_file:?}"))?;

        // Work around target sanity check added in
        // rust-lang/rust@09c076810cb7649e5817f316215010d49e78e8d7.
        let temp_dir = std::env::temp_dir().join("rustc-targets");
        if !temp_dir.exists() {
            std::fs::create_dir_all(&temp_dir)?;
        }
        std::fs::File::create(temp_dir.join("riscv32im-succinct-zkvm-elf.json"))?;

        // Build the toolchain.
        Command::new("python3")
            .env("RUST_TARGET_PATH", &temp_dir)
            .env("CARGO_TARGET_RISCV32IM_SUCCINCT_ZKVM_ELF_RUSTFLAGS", "-Cpasses=lower-atomic")
            .env("CARGO_TARGET_RISCV64IM_SUCCINCT_ZKVM_ELF_RUSTFLAGS", "-Cpasses=lower-atomic")
            .args([
                "x.py",
                "build",
                "--stage",
                "2",
                "compiler/rustc",
                "library",
                "--target",
                &format!(
                    "riscv32im-succinct-zkvm-elf,riscv64im-succinct-zkvm-elf,{}",
                    get_target()
                ),
            ])
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

        // Link the toolchain to rustup.
        Command::new("rustup")
            .args(["toolchain", "link", RUSTUP_TOOLCHAIN_NAME])
            .arg(&toolchain_dir)
            .run()?;
        println!("Successfully linked the toolchain to rustup.");

        // Compressing toolchain directory to tar.gz.
        let target = get_target();
        let tar_gz_path = format!("rust-toolchain-{target}.tar.gz");
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
        println!("Successfully compressed the toolchain to {tar_gz_path}.");

        Ok(())
    }
}
