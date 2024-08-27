use std::fs::File;

use anyhow::Result;
use clap::Parser;
use sp1_sdk::{HashableKey, ProverClient};
use std::io::Read;

#[derive(Parser)]
#[command(name = "vkey", about = "View the verification key hash for a program.")]
pub struct VkeyCmd {
    /// Path to the ELF.
    #[arg(long, required = true)]
    elf: String,
}

impl VkeyCmd {
    pub fn run(&self) -> Result<()> {
        // Read the elf file contents
        let mut file = File::open(self.elf.clone()).unwrap();
        let mut elf = Vec::new();
        file.read_to_end(&mut elf).unwrap();

        // Get the verification key
        let prover = ProverClient::new();
        let (_, vk) = prover.setup(&elf);

        // Print the verification key hash
        println!("Verification Key Hash:\n{}", vk.vk.bytes32());

        Ok(())
    }
}
