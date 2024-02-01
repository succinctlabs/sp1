use std::{env, process::Command};

use anyhow::Result;
use clap::Parser;
use succinct_core::{runtime::Program, utils};

use crate::CommandExecutor;

#[derive(Parser)]
#[command(name = "prove", about = "(default) Build and prove a Rust program")]
pub struct ProveCmd {
    #[clap(long)]
    target: Option<String>,

    #[clap(last = true)]
    cargo_args: Vec<String>,
}

impl ProveCmd {
    pub fn run(&self) -> Result<()> {
        let metadata_cmd = cargo_metadata::MetadataCommand::new();
        let metadata = metadata_cmd.exec().unwrap();

        Command::new("cargo").args(["build"]).run()?;
        let elf_path = metadata
            .workspace_root
            .join("elf")
            .join("riscv32im-succinct-zkvm-elf");
        let program = Program::from_elf(elf_path.as_str());

        utils::setup_logger();
        utils::prove(program);

        Ok(())
    }
}
