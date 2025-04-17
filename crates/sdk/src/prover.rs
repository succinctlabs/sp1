//! # SP1 Prover Trait
//!
//! A trait that each prover variant must implement.

use std::borrow::Borrow;

use anyhow::Result;
use itertools::Itertools;
use p3_field::PrimeField32;
use sp1_core_executor::{ExecutionReport, SP1Context};
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::io::SP1PublicValues;
use sp1_prover::{
    components::SP1ProverComponents, CoreSC, InnerSC, SP1CoreProofData, SP1Prover, SP1ProvingKey,
    SP1VerifyingKey, SP1_CIRCUIT_VERSION,
};
use sp1_stark::{air::PublicValues, MachineVerificationError, Word};
use thiserror::Error;

use crate::{
    install::try_install_circuit_artifacts, SP1Proof, SP1ProofMode, SP1ProofWithPublicValues,
};

/// A basic set of primitives that each prover variant must implement.
pub trait Prover<C: SP1ProverComponents>: Send + Sync {
    /// The inner [`SP1Prover`] struct used by the prover.
    fn inner(&self) -> &SP1Prover<C>;

    /// The version of the current SP1 circuit.
    fn version(&self) -> &str {
        SP1_CIRCUIT_VERSION
    }

    /// Generate the proving and verifying keys for the given program.
    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey);

    /// Executes the program on the given input.
    fn execute(&self, elf: &[u8], stdin: &SP1Stdin) -> Result<(SP1PublicValues, ExecutionReport)> {
        Ok(self.inner().execute(elf, stdin, SP1Context::default())?)
    }

    /// Proves the given program on the given input in the given proof mode.
    fn prove(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        mode: SP1ProofMode,
    ) -> Result<SP1ProofWithPublicValues>;

    /// Verify that an SP1 proof is valid given its vkey and metadata.
    /// For Plonk proofs, verifies that the public inputs of the `PlonkBn254` proof match
    /// the hash of the VK and the committed public values of the `SP1ProofWithPublicValues`.
    fn verify(
        &self,
        bundle: &SP1ProofWithPublicValues,
        vkey: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        verify_proof(self.inner(), self.version(), bundle, vkey)
    }
}

/// An error that occurs when calling [`Prover::verify`].
#[derive(Error, Debug)]
pub enum SP1VerificationError {
    /// An error that occurs when the public values are invalid.
    #[error("Invalid public values")]
    InvalidPublicValues,
    /// An error that occurs when the SP1 version does not match the version of the circuit.
    #[error("Version mismatch")]
    VersionMismatch(String),
    /// An error that occurs when the core machine verification fails.
    #[error("Core machine verification error: {0}")]
    Core(MachineVerificationError<CoreSC>),
    /// An error that occurs when the recursion verification fails.
    #[error("Recursion verification error: {0}")]
    Recursion(MachineVerificationError<InnerSC>),
    /// An error that occurs when the Plonk verification fails.
    #[error("Plonk verification error: {0}")]
    Plonk(anyhow::Error),
    /// An error that occurs when the Groth16 verification fails.
    #[error("Groth16 verification error: {0}")]
    Groth16(anyhow::Error),
    /// An error that occurs when the proof is invalid.
    #[error("Unexpected error: {0:?}")]
    Other(anyhow::Error),
}

/// In SP1, a proof's public values can either be hashed with SHA2 or Blake3. In SP1 V4, there is no
/// metadata attached to the proof about which hasher function was used for public values hashing.
/// Instead, when verifying the proof, the public values are hashed with SHA2 and Blake3, and
/// if either matches the `expected_public_values_hash`, the verification is successful.
///
/// The security for this verification in SP1 V4 derives from the fact that both SHA2 and Blake3 are
/// designed to be collision resistant. It is computationally infeasible to find an input i1 for
/// SHA256 and an input i2 for Blake3 that the same hash value. Doing so would require breaking both
/// algorithms simultaneously.
pub(crate) fn verify_proof<C: SP1ProverComponents>(
    prover: &SP1Prover<C>,
    version: &str,
    bundle: &SP1ProofWithPublicValues,
    vkey: &SP1VerifyingKey,
) -> Result<(), SP1VerificationError> {
    // Check that the SP1 version matches the version of the currentcircuit.
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
            // It is computationally infeasible to find two distinct inputs, one processed with
            // SHA256 and the other with Blake3, that yield the same hash value.
            if committed_value_digest_bytes != bundle.public_values.hash() &&
                committed_value_digest_bytes != bundle.public_values.blake3_hash()
            {
                return Err(SP1VerificationError::InvalidPublicValues);
            }

            // Verify the core proof.
            prover
                .verify(&SP1CoreProofData(proof.clone()), vkey)
                .map_err(SP1VerificationError::Core)
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
            // It is computationally infeasible to find two distinct inputs, one processed with
            // SHA256 and the other with Blake3, that yield the same hash value.
            if committed_value_digest_bytes != bundle.public_values.hash() &&
                committed_value_digest_bytes != bundle.public_values.blake3_hash()
            {
                return Err(SP1VerificationError::InvalidPublicValues);
            }

            prover.verify_compressed(proof, vkey).map_err(SP1VerificationError::Recursion)
        }
        SP1Proof::Plonk(proof) => prover
            .verify_plonk_bn254(
                proof,
                vkey,
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
                vkey,
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
