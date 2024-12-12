use itertools::Itertools;
use p3_field::PrimeField32;
use sp1_prover::components::DefaultProverComponents;
use std::borrow::Borrow;

use anyhow::Result;
use sp1_prover::{SP1CoreProofData, SP1Prover, SP1VerifyingKey};
use sp1_stark::{air::PublicValues, Word};

use crate::install::try_install_circuit_artifacts;
use crate::local::SP1VerificationError;
use crate::{proof::SP1Proof, proof::SP1ProofWithPublicValues};

/// Verify that an SP1 proof is valid given its vkey and metadata.
/// For Plonk proofs, verifies that the public inputs of the PlonkBn254 proof match
/// the hash of the VK and the committed public values of the SP1ProofWithPublicValues.
pub fn verify(
    prover: &SP1Prover<DefaultProverComponents>,
    version: &str,
    bundle: &SP1ProofWithPublicValues,
    vk: &SP1VerifyingKey,
) -> Result<(), SP1VerificationError> {
    if bundle.sp1_version != version {
        return Err(SP1VerificationError::VersionMismatch(bundle.sp1_version.clone()));
    }

    match &bundle.proof {
        SP1Proof::Core(proof) => {
            let public_values: &PublicValues<Word<_>, _> =
                proof.last().unwrap().public_values.as_slice().borrow();

            // Get the committed value digest bytes.
            let committed_value_digest_bytes = public_values
                .committed_value_digest
                .iter()
                .flat_map(|w| w.0.iter().map(|x| x.as_canonical_u32() as u8))
                .collect_vec();

            // Make sure the committed value digest matches the public values hash.
            for (a, b) in committed_value_digest_bytes.iter().zip_eq(bundle.public_values.hash()) {
                if *a != b {
                    return Err(SP1VerificationError::InvalidPublicValues);
                }
            }

            // Verify the core proof.
            prover.verify(&SP1CoreProofData(proof.clone()), vk).map_err(SP1VerificationError::Core)
        }
        SP1Proof::Compressed(proof) => {
            let public_values: &PublicValues<Word<_>, _> =
                proof.proof.public_values.as_slice().borrow();

            // Get the committed value digest bytes.
            let committed_value_digest_bytes = public_values
                .committed_value_digest
                .iter()
                .flat_map(|w| w.0.iter().map(|x| x.as_canonical_u32() as u8))
                .collect_vec();

            // Make sure the committed value digest matches the public values hash.
            for (a, b) in committed_value_digest_bytes.iter().zip_eq(bundle.public_values.hash()) {
                if *a != b {
                    return Err(SP1VerificationError::InvalidPublicValues);
                }
            }

            prover.verify_compressed(proof, vk).map_err(SP1VerificationError::Recursion)
        }
        SP1Proof::Plonk(proof) => prover
            .verify_plonk_bn254(
                proof,
                vk,
                &bundle.public_values,
                &if sp1_prover::build::sp1_dev_mode() {
                    sp1_prover::build::plonk_bn254_artifacts_dev_dir()
                } else {
                    try_install_circuit_artifacts("plonk")
                },
            )
            .map_err(SP1VerificationError::Plonk),
        SP1Proof::Groth16(proof) => prover
            .verify_groth16_bn254(
                proof,
                vk,
                &bundle.public_values,
                &if sp1_prover::build::sp1_dev_mode() {
                    sp1_prover::build::groth16_bn254_artifacts_dev_dir()
                } else {
                    try_install_circuit_artifacts("groth16")
                },
            )
            .map_err(SP1VerificationError::Groth16),
    }
}
