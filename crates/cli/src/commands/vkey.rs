use std::{fs::File, io::Read};

use anyhow::Result;
use clap::{Args, Parser};
use sp1_build::{generate_elf_paths, BuildArgs};
use sp1_sdk::{HashableKey, ProverClient};

#[derive(Parser)]
#[command(name = "vkey", about = "View the verification key hash for a program.")]
pub struct VkeyCmd {
    /// Path to the ELF.
    #[clap(flatten)]
    elf: Elf,
}

#[derive(Debug, Clone, Args)]
#[group(required = true, multiple = false)]
pub struct Elf {
    /// The path to the ELF file
    #[arg(long = "elf")]
    path: Option<String>,
    /// The crate used to generate the ELF file
    #[arg(long)]
    program: Option<String>,
}

impl VkeyCmd {
    pub fn run(&self) -> Result<()> {
        let elf_paths = if let Some(path) = &self.elf.path {
            vec![(None, path.clone())]
        } else if let Some(program) = &self.elf.program {
            let metadata_cmd = cargo_metadata::MetadataCommand::new();
            let metadata = metadata_cmd.exec()?;
            let build_args = BuildArgs { packages: vec![program.clone()], ..Default::default() };

            generate_elf_paths(&metadata, Some(&build_args))?
                .into_iter()
                .map(|(target, path)| (Some(target), path.to_string()))
                .collect()
        } else {
            unreachable!()
        };

        for (target, elf_path) in elf_paths {
            // Read the elf file contents
            let mut file = File::open(elf_path)?;
            let mut elf = Vec::new();
            file.read_to_end(&mut elf)?;

            // Get the verification key
            let prover = ProverClient::from_env();
            let (_, vk) = prover.setup(&elf);

            // Print the verification key hash
            if let Some(target) = target {
                println!("Verification Key Hash for '{target}':\n{}", vk.vk.bytes32());
            } else {
                println!("Verification Key Hash:\n{}", vk.vk.bytes32());
            }
        }

        Ok(())
    }
}
