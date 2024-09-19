use anyhow::Result;
use clap::Parser;
use sp1_build::check::CheckArgs;

#[derive(Parser)]
#[command(
    name = "check",
    about = "Check that a crate compiles for the Succinct target."
)]
pub struct CheckCmd {
    #[clap(flatten)]
    check_args: CheckArgs,
}

impl CheckCmd {
    pub fn run(&self) -> Result<()> {
        self.check_args.check_program(None)?;

        Ok(())
    }
}
