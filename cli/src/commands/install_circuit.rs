use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use reqwest::Client;
use sp1_sdk::artifacts::{get_artifacts_dir, install_circuit_artifacts, WrapCircuitType};
use std::{path::PathBuf, process::Command};

use crate::CommandExecutor;

#[derive(Clone, Debug, Copy, ValueEnum)]
pub enum ClapCircuitType {
    Groth16,
    Plonk,
}

impl Into<WrapCircuitType> for ClapCircuitType {
    fn into(self) -> WrapCircuitType {
        match self {
            ClapCircuitType::Groth16 => WrapCircuitType::Groth16,
            ClapCircuitType::Plonk => WrapCircuitType::Plonk,
        }
    }
}

#[derive(Parser)]
#[command(
    name = "install-circuit",
    about = "Install prebuilt artifacts for the Groth16 or Plonk wrapper circuit."
)]
pub struct InstallCircuitCmd {
    /// The type of circuit to build.
    #[clap(value_enum)]
    circuit_type: ClapCircuitType,

    /// The destination directory for the circuit artifacts to be in.
    /// Defaults to ~/.sp1/circuits/<type>/<CIRCUIT_VERSION>.
    #[clap(long)]
    build_dir: Option<String>,

    /// The version of the circuit to install.
    #[clap(long, default_value = "latest")]
    version: String,
}

impl InstallCircuitCmd {
    pub fn run(&self) -> Result<()> {
        let build_dir = if let Some(build_dir) = self.build_dir.clone() {
            PathBuf::from(build_dir)
        } else {
            get_artifacts_dir(self.circuit_type.into())
        };

        // If build_dir exists, confirm if user wants to overwrite
        if build_dir.exists() {
            let overwrite_existing = dialoguer::Confirm::new()
                .with_prompt(format!(
                    "Directory {} already exists. Do you want to overwrite it?",
                    build_dir.display()
                ))
                .interact()
                .context("Failed to get user input.")?;

            if !overwrite_existing {
                return Ok(());
            }
        }

        let version = match self.version.as_str() {
            "latest" => None,
            _ => Some(
                self.version
                    .parse::<u32>()
                    .context("Failed to parse version number.")?,
            ),
        };

        install_circuit_artifacts(self.circuit_type.into(), true, Some(build_dir), version)?;

        Ok(())
    }
}
