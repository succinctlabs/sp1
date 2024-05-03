mod local;
mod mock;
mod network;
mod utils;

use anyhow::Result;
pub use local::LocalProver;
pub use mock::MockProver;
pub use network::NetworkProver;
use sp1_prover::{SP1ProvingKey, SP1Stdin, SP1VerifyingKey};

use crate::{SP1CompressedProof, SP1Groth16Proof, SP1PlonkProof, SP1Proof};

/// An implementation of [crate::ProverClient].
pub trait Prover: Send + Sync {
    fn id(&self) -> String;

    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey);

    /// Prove the execution of a RISCV ELF with the given inputs.
    fn prove(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Proof>;

    /// Generate a compressed proof of the execution of a RISCV ELF with the given inputs.
    fn prove_compressed(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1CompressedProof>;

    /// Given an SP1 program and input, generate a Groth16 proof that can be verified on-chain.
    fn prove_groth16(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Groth16Proof>;

    /// Given an SP1 program and input, generate a PLONK proof that can be verified on-chain.
    fn prove_plonk(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1PlonkProof>;

    /// Verify that an SP1 proof is valid given its vkey and metadata.
    fn verify(&self, proof: &SP1Proof, vkey: &SP1VerifyingKey) -> Result<()>;

    /// Verify that a compressed SP1 proof is valid given its vkey and metadata.
    fn verify_compressed(&self, proof: &SP1CompressedProof, vkey: &SP1VerifyingKey) -> Result<()>;

    /// Verify that a SP1 PLONK proof is valid given its vkey and metadata.
    fn verify_plonk(&self, proof: &SP1PlonkProof, vkey: &SP1VerifyingKey) -> Result<()>;

    /// Verify that a SP1 Groth16 proof is valid given its vkey and metadata.
    fn verify_groth16(&self, proof: &SP1Groth16Proof, vkey: &SP1VerifyingKey) -> Result<()>;
}
