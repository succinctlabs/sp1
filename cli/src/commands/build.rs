use anyhow::Result;
use clap::Parser;
use sp1_build::{build_program, BuildArgs};

#[derive(Parser)]
#[command(name = "build", about = "Compile an SP1 program")]
pub struct BuildCmd {
    #[clap(flatten)]
    build_args: BuildArgs,
}

impl BuildCmd {
    pub fn run(&self) -> Result<()> {
        build_program(&self.build_args, None)?;

        Ok(())
    }
}
