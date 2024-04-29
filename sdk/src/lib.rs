#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
pub mod proto {
    #[rustfmt::skip]
    #[allow(clippy::all)]
    pub mod network;
}
pub mod auth;
pub mod client;
mod local;
mod mock;
mod network;
pub mod prove;
pub mod utils;

use anyhow::{Ok, Result};
use local::LocalProver;
use network::NetworkProver;
pub use sp1_prover::{
    CoreSC, SP1CoreProof, SP1Prover, SP1ProvingKey, SP1PublicValues, SP1Stdin, SP1VerifyingKey,
};
use sp1_prover::{Groth16Proof, InnerSC, PlonkBn254Proof};
use std::{env, fs::File, path::Path};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sp1_core::stark::ShardProof;

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

    pub fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }

    /// Proves the execution of the given elf with the given inputs.
    pub fn prove(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1DefaultProof> {
        self.prover.prove(pk, stdin)
    }

    /// Generates a compressed proof for the given elf and stdin.
    pub fn prove_compressed(
        &self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
    ) -> Result<SP1CompressedProof> {
        self.prover.prove_compressed(pk, stdin)
    }

    /// Generates a groth16 proof, verifiable onchain, of the given elf and stdin.
    pub fn prove_groth16(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Groth16Proof> {
        self.prover.prove_groth16(pk, stdin)
    }

    /// Generates a PLONK proof, verifiable onchain, of the given elf and stdin.
    pub fn prove_plonk(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1PlonkProof> {
        self.prover.prove_plonk(pk, stdin)
    }

    /// Verifies the given proof is valid and matches the given vkey.
    pub fn verify(&self, proof: &SP1DefaultProof, vkey: &SP1VerifyingKey) -> Result<()> {
        self.prover.verify(proof, vkey)
    }

    /// Verifies the given compressed proof is valid and matches the given vkey.
    pub fn verify_compressed(
        &self,
        proof: &SP1CompressedProof,
        vkey: &SP1VerifyingKey,
    ) -> Result<()> {
        self.prover.verify_compressed(proof, vkey)
    }

    /// Verifies the given groth16 proof is valid and matches the given vkey.
    pub fn verify_plonk(&self, proof: &SP1PlonkProof, vkey: &SP1VerifyingKey) -> Result<()> {
        self.prover.verify_plonk(proof, vkey)
    }

    /// Verifies the given groth16 proof is valid and matches the given vkey.
    pub fn verify_groth16(&self, proof: &SP1Groth16Proof, vkey: &SP1VerifyingKey) -> Result<()> {
        self.prover.verify_groth16(proof, vkey)
    }
}

#[derive(Serialize, Deserialize)]
pub struct ProofStatistics {
    pub cycle_count: u64,
    pub cost: u64,
    pub total_time: u64,
    pub latency: u64,
}

/// A proof of a RISCV ELF execution with given inputs and outputs.
#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "P: Serialize"))]
#[serde(bound(deserialize = "P: DeserializeOwned"))]
pub struct SP1ProofWithMetadata<P> {
    pub proof: P,
    pub stdin: SP1Stdin,
    pub public_values: SP1PublicValues,
}

impl<P: Serialize + DeserializeOwned> SP1ProofWithMetadata<P> {
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        bincode::serialize_into(File::create(path).expect("failed to open file"), self)
            .map_err(Into::into)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        bincode::deserialize_from(File::open(path).expect("failed to open file"))
            .map_err(Into::into)
    }
}

impl<P: std::fmt::Debug> std::fmt::Debug for SP1ProofWithMetadata<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SP1ProofWithMetadata")
            .field("proof", &self.proof)
            .finish()
    }
}

pub type SP1DefaultProof = SP1ProofWithMetadata<Vec<ShardProof<CoreSC>>>;

pub type SP1CompressedProof = SP1ProofWithMetadata<ShardProof<InnerSC>>;

pub type SP1PlonkProof = SP1ProofWithMetadata<PlonkBn254Proof>;

pub type SP1Groth16Proof = SP1ProofWithMetadata<Groth16Proof>;

pub trait Prover: Send + Sync {
    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey);

    /// Prove the execution of a RISCV ELF with the given inputs.
    fn prove(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1DefaultProof>;

    /// Generate a compressed proof of the execution of a RISCV ELF with the given inputs.
    fn prove_compressed(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1CompressedProof>;

    /// Given an SP1 program and input, generate a PLONK proof that can be verified on-chain.
    fn prove_plonk(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1PlonkProof>;

    /// Given an SP1 program and input, generate a Groth16 proof that can be verified on-chain.
    fn prove_groth16(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Groth16Proof>;

    /// Verify that an SP1 proof is valid given its vkey and metadata.
    fn verify(&self, proof: &SP1DefaultProof, vkey: &SP1VerifyingKey) -> Result<()>;

    /// Verify that a compressed SP1 proof is valid given its vkey and metadata.
    fn verify_compressed(&self, proof: &SP1CompressedProof, vkey: &SP1VerifyingKey) -> Result<()>;

    /// Verify that a SP1 PLONK proof is valid given its vkey and metadata.
    fn verify_plonk(&self, proof: &SP1PlonkProof, vkey: &SP1VerifyingKey) -> Result<()>;

    /// Verify that a SP1 Groth16 proof is valid given its vkey and metadata.
    fn verify_groth16(&self, proof: &SP1Groth16Proof, vkey: &SP1VerifyingKey) -> Result<()>;
}
