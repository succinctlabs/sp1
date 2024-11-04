use anyhow::{Context, Result};
use clap::Parser;
use sp1_build::{execute_build_program, BuildArgs};

/// Command for compiling an SP1 program
#[derive(Parser, Debug)]
#[command(name = "build", about = "Compile an SP1 program")]
pub struct BuildCmd {
    /// Build arguments for the SP1 program
    #[clap(flatten)]
    pub build_args: BuildArgs,
}

impl BuildCmd {
    /// Executes the build command with the provided arguments
    pub fn run(&self) -> Result<()> {
        execute_build_program(&self.build_args, None)
            .context("Failed to execute build program")?;

        Ok(())
    }

    /// Validates the build command arguments
    pub fn validate(&self) -> Result<()> {
        // Add any validation logic here if needed
        Ok(())
    }
}
