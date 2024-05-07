mod local;
mod mock;
mod network;

use crate::{SP1CompressedProof, SP1Groth16Proof, SP1PlonkProof, SP1Proof};
use anyhow::Result;
pub use local::LocalProver;
pub use mock::MockProver;
pub use network::NetworkProver;
use sha2::{Digest, Sha256};
use sp1_core::air::PublicValues;
use sp1_core::stark::MachineProof;
use sp1_core::stark::MachineVerificationError;
use sp1_core::stark::StarkGenericConfig;
use sp1_prover::CoreSC;
use sp1_prover::SP1Prover;
use sp1_prover::{SP1ProvingKey, SP1Stdin, SP1VerifyingKey};

/// An implementation of [crate::ProverClient].
pub trait Prover: Send + Sync {
    fn id(&self) -> String;

    fn sp1_prover(&self) -> &SP1Prover;

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
    fn verify(
        &self,
        proof: &SP1Proof,
        vkey: &SP1VerifyingKey,
    ) -> Result<(), MachineVerificationError<CoreSC>> {
        let pv = PublicValues::from_vec(proof.proof[0].public_values.clone());
        let pv_digest: [u8; 32] = Sha256::digest(proof.public_values.as_slice()).into();
        if pv_digest != *pv.commit_digest_bytes() {
            return Err(MachineVerificationError::InvalidPublicValuesDigest);
        }
        let machine_proof = MachineProof {
            shard_proofs: proof.proof.clone(),
        };
        let sp1_prover = self.sp1_prover();
        let mut challenger = sp1_prover.core_machine.config().challenger();
        sp1_prover
            .core_machine
            .verify(&vkey.vk, &machine_proof, &mut challenger)
    }

    /// Verify that a compressed SP1 proof is valid given its vkey and metadata.
    fn verify_compressed(&self, proof: &SP1CompressedProof, vkey: &SP1VerifyingKey) -> Result<()> {
        // TODO: implement verification of the digest of the public values matching
        let sp1_prover = self.sp1_prover();
        let machine_proof = MachineProof {
            shard_proofs: vec![proof.proof.clone()],
        };
        let mut challenger = sp1_prover.compress_machine.config().challenger();
        Ok(sp1_prover
            .compress_machine
            .verify(&vkey.vk, &machine_proof, &mut challenger)?)
    }

    /// Verify that a SP1 Groth16 proof is valid given its vkey and metadata.
    fn verify_groth16(&self, _proof: &SP1Groth16Proof, _vkey: &SP1VerifyingKey) -> Result<()> {
        Ok(())
    }

    /// Verify that a SP1 PLONK proof is valid given its vkey and metadata.
    fn verify_plonk(&self, _proof: &SP1PlonkProof, _vkey: &SP1VerifyingKey) -> Result<()> {
        Ok(())
    }
}
