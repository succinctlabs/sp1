#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
pub mod proto {
    #[rustfmt::skip]
    #[allow(clippy::all)]
    pub mod network;
}
pub mod auth;
pub mod client;
pub mod prove;
pub mod utils;

use anyhow::{Ok, Result};
use prove::{LocalProver, NetworkProver, Prover};
pub use sp1_prover::{CoreSC, SP1CoreProof, SP1Prover, SP1PublicValues, SP1Stdin};
use std::env;

/// A client that can prove RISCV ELFs and verify those proofs.
pub struct ProverClient {
    pub prover: Box<dyn Prover>,
}

impl Default for ProverClient {
    fn default() -> Self {
        Self::new()
    }
}

impl ProverClient {
    /// Creates a new ProverClient with the prover set to either local or remote based on the
    /// SP1_PROVER environment variable.
    pub fn new() -> Self {
        dotenv::dotenv().ok();
        match env::var("SP1_PROVER")
            .unwrap_or("local".to_string())
            .to_lowercase()
            .as_str()
        {
            "local" => Self {
                prover: Box::new(LocalProver::new()),
            },
            "remote" => Self {
                prover: Box::new(NetworkProver::new()),
            },
            _ => panic!("Invalid SP1_PROVER value"),
        }
    }

    /// Executes the elf with the given inputs and returns the output.
    pub fn execute(elf: &[u8], stdin: SP1Stdin) -> Result<SP1PublicValues> {
        Ok(SP1Prover::execute(elf, &stdin))
    }
}

impl Prover for ProverClient {
    fn prove(&self, elf: &[u8], stdin: SP1Stdin) -> Result<prove::SP1DefaultProof> {
        self.prover.prove(elf, stdin)
    }

    fn prove_compressed(&self, elf: &[u8], stdin: SP1Stdin) -> Result<prove::SP1CompressedProof> {
        self.prover.prove_compressed(elf, stdin)
    }

    fn prove_groth16(&self, elf: &[u8], stdin: SP1Stdin) -> Result<prove::SP1Groth16Proof> {
        self.prover.prove_groth16(elf, stdin)
    }

    fn prove_plonk(&self, elf: &[u8], stdin: SP1Stdin) -> Result<prove::SP1PlonkProof> {
        self.prover.prove_plonk(elf, stdin)
    }

    fn verify(
        &self,
        proof: prove::SP1DefaultProof,
        vkey: &sp1_prover::SP1VerifyingKey,
    ) -> Result<()> {
        self.prover.verify(proof, vkey)
    }

    fn verify_compressed(
        &self,
        proof: prove::SP1CompressedProof,
        vkey: &sp1_prover::SP1VerifyingKey,
    ) -> Result<()> {
        self.prover.verify_compressed(proof, vkey)
    }

    fn verify_plonk(
        &self,
        proof: prove::SP1PlonkProof,
        vkey: &sp1_prover::SP1VerifyingKey,
    ) -> Result<()> {
        self.prover.verify_plonk(proof, vkey)
    }

    fn verify_groth16(
        &self,
        proof: prove::SP1Groth16Proof,
        vkey: &sp1_prover::SP1VerifyingKey,
    ) -> Result<()> {
        self.prover.verify_groth16(proof, vkey)
    }
}
