use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use reqwest::Client;
use sp1_prover::build::{GROTH16_CIRCUIT_VERSION, PLONK_BN254_CIRCUIT_VERSION};
use sp1_sdk::artifacts::WrapCircuitType;
use std::process::Command;

use crate::{download_file, CommandExecutor};

#[derive(Parser)]
#[command(
    name = "install-circuit",
    about = "Install prebuilt artifacts for the Groth16 or Plonk wrapper circuit."
)]
pub struct InstallCircuitCmd {
    /// The type of circuit to build.
    #[clap(value_enum)]
    circuit_type: WrapCircuitType,

    /// The destination directory for the circuit artifacts to be in.
    /// Defaults to ~/.sp1/circuits/<type>/<CIRCUIT_VERSION>.
    #[clap(long)]
    build_dir: Option<String>,

    /// The version of the circuit to install.
    #[clap(long, default_value = "latest")]
    version: String,
}

const CIRCUIT_ARTIFACTS_URL: &str = "https://sp1-circuits.s3-us-east-2.amazonaws.com/";

impl InstallCircuitCmd {
    pub fn run(&self) -> Result<()> {
        // Build dir: ~/.sp1/circuits/<type>/<CIRCUIT_VERSION>
        let build_dir = self.build_dir.clone().map(|b| b.into()).unwrap_or_else(|| {
            let home_dir = dirs::home_dir().expect("Failed to get home directory.");
            home_dir
                .join(".sp1")
                .join("circuits")
                .join(match self.circuit_type {
                    CircuitType::Groth16 => format!("{}/v{}", "groth16", GROTH16_CIRCUIT_VERSION),
                    CircuitType::Plonk => {
                        format!("{}/v{}", "plonk", PLONK_BN254_CIRCUIT_VERSION)
                    }
                })
        });

        // If dir exists, ask if user wants to overwrite.
        if build_dir.exists() {
            let prompt = format!(
                "Directory {} already exists. Do you want to overwrite it?",
                build_dir.display()
            );
            let response = dialoguer::Confirm::new().with_prompt(prompt).interact()?;
            if !response {
                return Ok(());
            }
            // Delete existing directory.
            std::fs::remove_dir_all(&build_dir)
                .context("Failed to remove existing build directory.")?;
        }

        println!(
            "Building {:?} artifacts in {}",
            self.circuit_type,
            build_dir.display()
        );

        // Mkdir
        std::fs::create_dir_all(&build_dir).context("Failed to create build directory.")?;

        // Download to a temporary file.
        let temp_dir = tempfile::tempdir()?;
        let temp_file_path = temp_dir.path().join("circuit.tar.gz");
        let mut temp_file = std::fs::File::create(&temp_file_path)?;
        let version_num = if self.version == "latest" {
            match self.circuit_type {
                CircuitType::Groth16 => GROTH16_CIRCUIT_VERSION,
                CircuitType::Plonk => PLONK_BN254_CIRCUIT_VERSION,
            }
        } else {
            self.version
                .parse::<u32>()
                .expect("Invalid version number.")
        };
        let download_url = format!(
            "{}{}/v{}.tar.gz",
            CIRCUIT_ARTIFACTS_URL, self.circuit_type, version_num
        );
        println!("Downloading {} to {:?}", download_url, temp_file);

        let rt = tokio::runtime::Runtime::new()?;
        let client = Client::builder().build()?;
        rt.block_on(download_file(&client, &download_url, &mut temp_file))
            .unwrap();

        // Extract the tarball to the build directory.
        Command::new("tar")
            .current_dir(temp_dir)
            .args([
                "-xzf",
                temp_file_path.to_str().unwrap(),
                "-C",
                build_dir.to_str().unwrap(),
            ])
            .run()?;

        Ok(())
    }
}
