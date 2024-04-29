use std::path::PathBuf;

use crate::{
    Prover, SP1CompressedProof, SP1DefaultProof, SP1Groth16Proof, SP1PlonkProof,
    SP1ProofWithMetadata, SP1ProvingKey, SP1VerifyingKey,
};
use anyhow::Result;
use sha2::{Digest, Sha256};
use sp1_core::{
    air::PublicValues,
    stark::{MachineProof, StarkGenericConfig},
};
use sp1_prover::{SP1Prover, SP1Stdin};

pub struct LocalProver {
    pub(crate) prover: SP1Prover,
}

impl Default for LocalProver {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalProver {
    pub fn new() -> Self {
        let prover = SP1Prover::new();
        Self { prover }
    }

    /// Get artifacts dir from SP1_CIRCUIT_DIR env var.
    fn get_artifacts_dir(&self) -> PathBuf {
        let artifacts_dir =
            std::env::var("SP1_CIRCUIT_DIR").expect("SP1_CIRCUIT_DIR env var not set");
        PathBuf::from(artifacts_dir)
    }
}

impl Prover for LocalProver {
    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }

    fn prove(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1DefaultProof> {
        let proof = self.prover.prove_core(pk, &stdin);
        Ok(SP1ProofWithMetadata {
            proof: proof.shard_proofs,
            stdin: proof.stdin,
            public_values: proof.public_values,
        })
    }

    fn prove_compressed(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1CompressedProof> {
        let proof = self.prover.prove_core(pk, &stdin);
        let deferred_proofs = stdin.proofs.iter().map(|p| p.0.clone()).collect();
        let public_values = proof.public_values.clone();
        let reduce_proof = self.prover.reduce(&pk.vk, proof, deferred_proofs);
        Ok(SP1CompressedProof {
            proof: reduce_proof.proof,
            stdin,
            public_values,
        })
    }

    fn prove_groth16(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Groth16Proof> {
        let artifacts_dir = self.get_artifacts_dir();
        let proof = self.prover.prove_core(pk, &stdin);
        let deferred_proofs = stdin.proofs.iter().map(|p| p.0.clone()).collect();
        let public_values = proof.public_values.clone();
        let reduce_proof = self.prover.reduce(&pk.vk, proof, deferred_proofs);
        let compress_proof = self.prover.compress(&pk.vk, reduce_proof);
        let outer_proof = self.prover.wrap_bn254(&pk.vk, compress_proof);
        let proof = self.prover.wrap_groth16(outer_proof, artifacts_dir);
        Ok(SP1ProofWithMetadata {
            proof,
            stdin,
            public_values,
        })
    }

    fn prove_plonk(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1PlonkProof> {
        let artifacts_dir = self.get_artifacts_dir();
        let proof = self.prover.prove_core(pk, &stdin);
        let deferred_proofs = stdin.proofs.iter().map(|p| p.0.clone()).collect();
        let public_values = proof.public_values.clone();
        let reduce_proof = self.prover.reduce(&pk.vk, proof, deferred_proofs);
        let compress_proof = self.prover.compress(&pk.vk, reduce_proof);
        let outer_proof = self.prover.wrap_bn254(&pk.vk, compress_proof);
        let proof = self.prover.wrap_plonk(outer_proof, artifacts_dir);
        Ok(SP1ProofWithMetadata {
            proof,
            stdin,
            public_values,
        })
    }

    fn verify(&self, proof: &SP1DefaultProof, vkey: &SP1VerifyingKey) -> Result<()> {
        let pv = PublicValues::from_vec(proof.proof[0].public_values.clone());
        let pv_digest: [u8; 32] = Sha256::digest(&proof.public_values.buffer.data).into();
        if pv_digest != *pv.commit_digest_bytes() {
            return Err(anyhow::anyhow!("Public values digest mismatch"));
        }
        let machine_proof = MachineProof {
            shard_proofs: proof.proof.clone(),
        };
        let mut challenger = self.prover.core_machine.config().challenger();
        Ok(self
            .prover
            .core_machine
            .verify(&vkey.vk, &machine_proof, &mut challenger)?)
    }

    fn verify_compressed(&self, proof: &SP1CompressedProof, vkey: &SP1VerifyingKey) -> Result<()> {
        todo!()
    }

    fn verify_groth16(&self, proof: &SP1Groth16Proof, vkey: &SP1VerifyingKey) -> Result<()> {
        todo!()
    }

    fn verify_plonk(&self, proof: &SP1PlonkProof, vkey: &SP1VerifyingKey) -> Result<()> {
        todo!()
    }
}
