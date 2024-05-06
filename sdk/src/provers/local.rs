use anyhow::Result;
use sp1_prover::{SP1Prover, SP1Stdin};

use super::utils;
use crate::{
    Prover, SP1CompressedProof, SP1Groth16Proof, SP1PlonkProof, SP1Proof, SP1ProofWithPublicValues,
    SP1ProvingKey, SP1VerifyingKey,
};

/// An implementation of [crate::ProverClient] that can generate end-to-end proofs locally.
pub struct LocalProver {
    prover: SP1Prover,
}

impl LocalProver {
    /// Creates a new [LocalProver].
    pub fn new() -> Self {
        let prover = SP1Prover::new();
        Self { prover }
    }
}

impl Prover for LocalProver {
    fn id(&self) -> String {
        "local".to_string()
    }

    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }

    fn sp1_prover(&self) -> &SP1Prover {
        &self.prover
    }

    fn prove(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Proof> {
        let proof = self.prover.prove_core(pk, &stdin);
        Ok(SP1ProofWithPublicValues {
            proof: proof.proof.0,
            stdin: proof.stdin,
            public_values: proof.public_values,
        })
    }

    fn prove_compressed(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1CompressedProof> {
        let proof = self.prover.prove_core(pk, &stdin);
        let deferred_proofs = stdin.proofs.iter().map(|p| p.0.clone()).collect();
        let public_values = proof.public_values.clone();
        let reduce_proof = self.prover.compress(&pk.vk, proof, deferred_proofs);
        Ok(SP1CompressedProof {
            proof: reduce_proof.proof,
            stdin,
            public_values,
        })
    }

    fn prove_groth16(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Groth16Proof> {
        let proof = self.prover.prove_core(pk, &stdin);
        let deferred_proofs = stdin.proofs.iter().map(|p| p.0.clone()).collect();
        let public_values = proof.public_values.clone();
        let reduce_proof = self.prover.compress(&pk.vk, proof, deferred_proofs);
        let compress_proof = self.prover.shrink(reduce_proof);
        let outer_proof = self.prover.wrap_bn254(compress_proof);

        // If `SP1_GROTH16_DEV_MODE` is enabled, we will compile a smaller version of the final
        // circuit and rebuild it for every proof.
        //
        // This is useful for development and testing purposes, as it allows us to test the
        // end-to-end proving without having to wait for the circuit to compile or download.
        let artifacts_dir = if utils::groth16_dev_mode() {
            tracing::debug!("proving groth16 inside development mode");
            let build_dir = tempfile::tempdir()
                .expect("failed to create temporary directory")
                .into_path();
            if let Err(err) = std::fs::create_dir_all(&build_dir) {
                panic!(
                    "failed to create build directory for groth16 artifacts: {}",
                    err
                );
            }
            sp1_prover::build::groth16_artifacts(
                &self.prover.wrap_vk,
                &outer_proof,
                build_dir.clone(),
            );
            build_dir
        }
        // If `SP1_GROTH16_ARTIFACTS_DIR` is set, we will use the artifacts from that directory.
        //
        // This is useful for when you want to test the production circuit and have a local build
        // available for development purposes.
        else if let Some(artifacts_dir) = utils::groth16_artifacts_dir() {
            artifacts_dir
        }
        // Otherwise, assume this is an official release and download the artifacts from the
        // official download url.
        else {
            sp1_prover::install::groth16_artifacts();
            sp1_prover::install::groth16_artifacts_dir()
        };

        let proof = self.prover.wrap_groth16(outer_proof, artifacts_dir);
        Ok(SP1ProofWithPublicValues {
            proof,
            stdin,
            public_values,
        })
    }

    fn prove_plonk(&self, _pk: &SP1ProvingKey, _stdin: SP1Stdin) -> Result<SP1PlonkProof> {
        // let proof = self.prover.prove_core(pk, &stdin);
        // let deferred_proofs = stdin.proofs.iter().map(|p| p.0.clone()).collect();
        // let public_values = proof.public_values.clone();
        // let reduce_proof = self.prover.compress(&pk.vk, proof, deferred_proofs);
        // let compress_proof = self.prover.shrink(&pk.vk, reduce_proof);
        // let outer_proof = self.prover.wrap_bn254(&pk.vk, compress_proof);
        // let proof = self.prover.wrap_plonk(outer_proof, artifacts_dir);
        // Ok(SP1ProofWithPublicValues {
        //     proof,
        //     stdin,
        //     public_values,
        // })
        todo!()
    }
}

impl Default for LocalProver {
    fn default() -> Self {
        Self::new()
    }
}
