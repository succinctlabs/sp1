use anyhow::Result;
use clap::{Parser, Subcommand};
use sp1_cli::{
    commands::{
        build::BuildCmd, build_toolchain::BuildToolchainCmd,
        install_toolchain::InstallToolchainCmd, new::NewCmd, prove::ProveCmd, trace::TraceCmd,
    },
    SP1_VERSION_MESSAGE,
};

#[derive(Parser)]
#[command(name = "cargo", bin_name = "cargo")]
pub enum Cargo {
    Prove(ProveCli),
}

#[derive(clap::Args)]
#[command(author, about, long_about = None, args_conflicts_with_subcommands = true, version = SP1_VERSION_MESSAGE)]
pub struct ProveCli {
    #[clap(subcommand)]
    pub command: Option<ProveCliCommands>,

    #[clap(flatten)]
    pub prove: ProveCmd,
}

#[derive(Subcommand)]
pub enum ProveCliCommands {
    New(NewCmd),
    Build(BuildCmd),
    Prove(ProveCmd),
    BuildToolchain(BuildToolchainCmd),
    InstallToolchain(InstallToolchainCmd),
    Trace(TraceCmd),
}

fn main() -> Result<()> {
    let Cargo::Prove(args) = Cargo::parse();
    let command = args.command.unwrap_or(ProveCliCommands::Prove(args.prove));
    match command {
        ProveCliCommands::New(cmd) => cmd.run(),
        ProveCliCommands::Build(cmd) => cmd.run(),
        ProveCliCommands::Prove(cmd) => cmd.run(),
        ProveCliCommands::BuildToolchain(cmd) => cmd.run(),
        ProveCliCommands::InstallToolchain(cmd) => cmd.run(),
        ProveCliCommands::Trace(cmd) => cmd.run(),
    }
}
