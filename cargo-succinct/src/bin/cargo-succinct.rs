use anyhow::Result;
use cargo_succinct::commands::build::BuildCmd;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cargo", bin_name = "cargo")]
pub enum Cargo {
    Succinct(Succinct),
}

#[derive(clap::Args)]
#[command(author, version, about, long_about = None)]
pub struct Succinct {
    #[clap(subcommand)]
    pub command: SuccinctCmd,
}

#[derive(Subcommand)]
pub enum SuccinctCmd {
    Build(BuildCmd),
}

fn main() -> Result<()> {
    let Cargo::Succinct(args) = Cargo::parse();
    match args.command {
        SuccinctCmd::Build(cmd) => cmd.run(),
    }
}
