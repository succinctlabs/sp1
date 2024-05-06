#![allow(unused_variables)]

use std::path::PathBuf;

use crate::{
    artifacts::{
        build_circuit_artifacts, get_artifacts_dir, get_dev_mode, install_circuit_artifacts,
        WrapCircuitType,
    },
    utils::EnvVarGuard,
    Prover, SP1Groth16ProofData, SP1PlonkProofData, SP1ProofWithMetadata, SP1ProvingKey,
    SP1VerifyingKey,
};
use anyhow::Result;
use sp1_prover::{
    SP1CoreProof, SP1Groth16Proof, SP1PlonkProof, SP1Prover, SP1ReducedProof, SP1ReducedProofData,
    SP1Stdin,
};

pub struct LocalProver {
    pub prover: SP1Prover,
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

    /// Initialize circuit artifacts by installing or building if in dev mode.
    pub(crate) fn initialize_circuit(&self, circuit_type: WrapCircuitType) -> PathBuf {
        let is_dev_mode = get_dev_mode();
        let artifacts_dir = get_artifacts_dir(circuit_type, is_dev_mode);

        if !artifacts_dir.exists() {
            log::info!("First time initializing circuit artifacts");
        }

        if is_dev_mode {
            build_circuit_artifacts(circuit_type, false, Some(artifacts_dir.clone()))
                .expect("Failed to build circuit artifacts.")
        } else {
            install_circuit_artifacts(
                WrapCircuitType::Groth16,
                false,
                Some(artifacts_dir.clone()),
                None,
            )
            .expect("Failed to install circuit artifacts");
        }
        artifacts_dir
    }
}

impl Prover for LocalProver {
    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }

    fn prove(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1CoreProof> {
        let proof = self.prover.prove_core(pk, &stdin);
        Ok(proof)
    }

    fn prove_reduced(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1ReducedProof> {
        let proof = self.prover.prove_core(pk, &stdin);
        let deferred_proofs = stdin.proofs.iter().map(|p| p.0.clone()).collect();
        let public_values = proof.public_values.clone();
        let _guard = EnvVarGuard::new("RECONSTRUCT_COMMITMENTS", "false");
        let reduce_proof = self.prover.reduce(&pk.vk, proof.proof, deferred_proofs);
        Ok(SP1ReducedProof {
            proof: SP1ReducedProofData(reduce_proof.proof),
            stdin,
            public_values,
        })
    }

    fn prove_groth16(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Groth16Proof> {
        let artifacts_dir = self.initialize_circuit(WrapCircuitType::Groth16);
        let proof = self.prover.prove_core(pk, &stdin);
        let deferred_proofs = stdin.proofs.iter().map(|p| p.0.clone()).collect();
        let public_values = proof.public_values.clone();
        let _guard = EnvVarGuard::new("RECONSTRUCT_COMMITMENTS", "false");
        let reduce_proof = self.prover.reduce(&pk.vk, proof.proof, deferred_proofs);
        let compress_proof = self.prover.compress(&pk.vk, reduce_proof);
        let outer_proof = self.prover.wrap_bn254(&pk.vk, compress_proof);
        let proof = self.prover.wrap_groth16(outer_proof, artifacts_dir);
        Ok(SP1Groth16Proof {
            proof: SP1Groth16ProofData(proof),
            stdin,
            public_values,
        })
    }

    fn prove_plonk(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1PlonkProof> {
        let artifacts_dir = self.initialize_circuit(WrapCircuitType::Plonk);
        let proof = self.prover.prove_core(pk, &stdin);
        let deferred_proofs = stdin.proofs.iter().map(|p| p.0.clone()).collect();
        let public_values = proof.public_values.clone();
        let _guard = EnvVarGuard::new("RECONSTRUCT_COMMITMENTS", "false");
        let reduce_proof = self.prover.reduce(&pk.vk, proof.proof, deferred_proofs);
        let compress_proof = self.prover.compress(&pk.vk, reduce_proof);
        let outer_proof = self.prover.wrap_bn254(&pk.vk, compress_proof);
        let proof = self.prover.wrap_plonk(outer_proof, artifacts_dir);
        Ok(SP1ProofWithMetadata {
            proof: SP1PlonkProofData(proof),
            stdin,
            public_values,
        })
    }

    fn verify(&self, proof: &SP1CoreProof, vkey: &SP1VerifyingKey) -> Result<()> {
        self.prover.verify(&proof.proof, vkey).map_err(|e| e.into())
    }

    fn verify_reduced(&self, proof: &SP1ReducedProof, vkey: &SP1VerifyingKey) -> Result<()> {
        self.prover
            .verify_reduced(&proof.proof, vkey)
            .map_err(|e| e.into())
    }

    fn verify_groth16(&self, proof: &SP1Groth16Proof, vkey: &SP1VerifyingKey) -> Result<()> {
        todo!()
    }

    fn verify_plonk(&self, proof: &SP1PlonkProof, vkey: &SP1VerifyingKey) -> Result<()> {
        todo!()
    }
}
