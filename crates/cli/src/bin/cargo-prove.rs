use anyhow::Result;
use clap::{Parser, Subcommand};

use sp1_cli::{
    commands::{build_toolchain::BuildToolchainCmd, install_toolchain::InstallToolchainCmd},
    SP1_VERSION_MESSAGE,
};

#[cfg(feature = "full")]
use sp1_cli::commands::{build::BuildCmd, new::NewCmd, vkey::VkeyCmd};

#[derive(Parser)]
#[command(name = "cargo", bin_name = "cargo")]
pub enum Cargo {
    Prove(ProveCli),
}

#[derive(clap::Args)]
#[command(author, about, long_about = None, args_conflicts_with_subcommands = true, version = SP1_VERSION_MESSAGE)]
pub struct ProveCli {
    #[command(subcommand)]
    pub command: ProveCliCommands,
}

#[derive(Subcommand)]
pub enum ProveCliCommands {
    #[cfg(feature = "full")]
    New(NewCmd),
    #[cfg(feature = "full")]
    Build(BuildCmd),
    #[cfg(feature = "full")]
    Vkey(VkeyCmd),
    BuildToolchain(BuildToolchainCmd),
    InstallToolchain(InstallToolchainCmd),
}

#[tokio::main]
async fn main() -> Result<()> {
    let Cargo::Prove(args) = Cargo::parse();

    match args.command {
        #[cfg(feature = "full")]
        ProveCliCommands::New(cmd) => cmd.run(),
        #[cfg(feature = "full")]
        ProveCliCommands::Build(cmd) => cmd.run(),
        #[cfg(feature = "full")]
        ProveCliCommands::Vkey(cmd) => cmd.run().await,
        ProveCliCommands::BuildToolchain(cmd) => cmd.run(),
        ProveCliCommands::InstallToolchain(cmd) => cmd.run().await,
    }
}
