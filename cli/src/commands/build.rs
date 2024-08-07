use anyhow::Result;
use clap::Parser;
use sp1_build::{execute_build_program, BuildArgs};

#[derive(Parser)]
#[command(name = "build", about = "Compile an SP1 program")]
pub struct BuildCmd {
    #[clap(flatten)]
    build_args: BuildArgs,
}

impl BuildCmd {
    pub fn run(&self) -> Result<()> {
        execute_build_program(&self.build_args, None)?;

        Ok(())
    }
}
