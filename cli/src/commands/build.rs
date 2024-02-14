use crate::build::build_program;
use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(name = "build", about = "Build a program")]
pub struct BuildCmd {
    #[clap(long, action)]
    verbose: bool,
}

impl BuildCmd {
    pub fn run(&self) -> Result<()> {
        build_program()?;

        Ok(())
    }
}
