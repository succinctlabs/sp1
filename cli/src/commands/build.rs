use crate::build::{build_program, BuildArgs};
use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(name = "build", about = "Build a program")]
pub struct BuildCmd {
    #[clap(long, action)]
    verbose: bool,

    #[clap(flatten)]
    build_args: BuildArgs,
}

impl BuildCmd {
    pub fn run(&self) -> Result<()> {
        build_program(&self.build_args)?;

        Ok(())
    }
}
