use anyhow::Result;
use clap::Parser;
use std::process::Command;
use succinct_core::{
    runtime::{Program, Runtime},
    utils::{self, prove_core},
};

use crate::CommandExecutor;

#[derive(Parser)]
#[command(name = "prove", about = "(default) Build and prove a Rust program")]
pub struct ProveCmd {
    #[clap(long)]
    input: Vec<u32>,

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
        let mut runtime = Runtime::new(program);
        for input in self.input.clone() {
            runtime.add_input(&input);
        }
        runtime.run();
        prove_core(&mut runtime);

        Ok(())
    }
}
