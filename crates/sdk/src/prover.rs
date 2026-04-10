//! # SP1 Prover Trait
//!
//! A trait that each prover variant must implement.

use crate::StatusCode;
use anyhow::Result;
use itertools::Itertools;
use num_bigint::BigUint;
use sp1_core_machine::io::SP1Stdin;
use sp1_hypercube::PrimeField32;
use sp1_hypercube::{air::PublicValues, PROOF_MAX_NUM_PVS};
use sp1_primitives::types::Elf;
use sp1_prover::{
    verify::verify_public_values, worker::SP1NodeCore, SP1VerifyingKey, SP1_CIRCUIT_VERSION,
};
use sp1_recursion_executor::RecursionPublicValues;
use std::{
    borrow::Borrow,
    fmt,
    future::{Future, IntoFuture},
    str::FromStr,
};
use thiserror::Error;

/// The module that exposes the [`ExecuteRequest`] type.
mod execute;

/// The module that exposes the [`ProveRequest`] trait.
mod prove;

pub use execute::ExecuteRequest;
pub(crate) use prove::BaseProveRequest;
pub use prove::{ProveRequest, SP1ProvingKey};

use crate::{SP1Proof, SP1ProofWithPublicValues};

/// The entire user-facing functionality of a prover.
pub trait Prover: Clone + Send + Sync {
    /// The proving key used for this prover type.
    type ProvingKey: ProvingKey;

    /// The possible errors that can occur when proving.
    type Error: fmt::Debug + fmt::Display;

    /// The prove request builder.
    type ProveRequest<'a>: ProveRequest<'a, Self>
    where
        Self: 'a;

    /// The inner [`LocalProver`] struct used by the prover.
    fn inner(&self) -> &SP1NodeCore;

    /// The version of the current SP1 circuit.
    fn version(&self) -> &str {
        SP1_CIRCUIT_VERSION
    }

    /// Setup the prover with the given ELF.
    fn setup(&self, elf: Elf) -> impl SendFutureResult<Self::ProvingKey, Self::Error>;

    /// Prove the given program on the given input in the given proof mode.
    fn prove<'a>(&'a self, pk: &'a Self::ProvingKey, stdin: SP1Stdin) -> Self::ProveRequest<'a>;

    /// Execute the program on the given input.
    fn execute(&self, elf: Elf, stdin: SP1Stdin) -> ExecuteRequest<'_, Self> {
        ExecuteRequest::new(self, elf, stdin)
    }

    /// Verify the given proof.
    ///
    /// Note: If the status code is not set, the verification process will check for success.
    fn verify(
        &self,
        proof: &SP1ProofWithPublicValues,
        vkey: &SP1VerifyingKey,
        status_code: Option<StatusCode>,
    ) -> Result<(), SP1VerificationError> {
        verify_proof(self.inner(), self.version(), proof, vkey, status_code)
    }
}

/// A trait that represents a prover's proving key.
pub trait ProvingKey: Clone + Send + Sync {
    /// Get the verifying key corresponding to the proving key.
    fn verifying_key(&self) -> &SP1VerifyingKey;

    /// Get the ELF corresponding to the proving key.
    fn elf(&self) -> &Elf;
}

/// A trait for [`Future`]s that are send and return a [`Result`].
///
/// This is just slightly better for the [`_Prover`] trait signature.
pub trait SendFutureResult<T, E>: Future<Output = Result<T, E>> + Send {}

impl<F, T, E> SendFutureResult<T, E> for F where F: Future<Output = Result<T, E>> + Send {}

/// A trait for [`IntoFuture`]s that are send and return a [`Result`].
///
/// This is just slightly better for the [`_Prover`] trait signature.
pub trait IntoSendFutureResult<T, E>: IntoFuture<Output = Result<T, E>> + Send {}

impl<F, T, E> IntoSendFutureResult<T, E> for F where F: IntoFuture<Output = Result<T, E>> + Send {}

/// An error that occurs when calling [`Prover::verify`].
#[derive(Error, Debug)]
pub enum SP1VerificationError {
    /// An error that occurs when the public values are invalid.
    #[error("Invalid public values")]
    InvalidPublicValues,
    /// An error that occurs when the SP1 version does not match the version of the circuit.
    #[error("Version mismatch: {0}")]
    VersionMismatch(String),
    /// An error that occurs when the core machine verification fails.
    #[error("Core machine verification error: {0}")]
    Core(anyhow::Error),
    /// An error that occurs when the recursion verification fails.
    #[error("Recursion verification error: {0}")]
    Recursion(anyhow::Error),
    /// An error that occurs when the Plonk verification fails.
    #[error("Plonk verification error: {0}")]
    Plonk(anyhow::Error),
    /// An error that occurs when the Groth16 verification fails.
    #[error("Groth16 verification error: {0}")]
    Groth16(anyhow::Error),
    /// An error that occurs when the proof is invalid.
    #[error("Unexpected error: {0:?}")]
    Other(anyhow::Error),
    /// An error that occurs when the exit code is unexpected.
    #[error("Unexpected exit code: {0}")]
    UnexpectedExitCode(u32),
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
pub(crate) fn verify_proof(
    node: &SP1NodeCore,
    version: &str,
    bundle: &SP1ProofWithPublicValues,
    vkey: &SP1VerifyingKey,
    status_code: Option<StatusCode>,
) -> Result<(), SP1VerificationError> {
    let status_code = status_code.unwrap_or(StatusCode::SUCCESS);

    // Check that the SP1 version matches the version of the current circuit.
    if bundle.sp1_version != version {
        return Err(SP1VerificationError::VersionMismatch(bundle.sp1_version.clone()));
    }

    match &bundle.proof {
        SP1Proof::Core(proof) => {
            if proof.is_empty() {
                return Err(SP1VerificationError::Core(anyhow::anyhow!("Empty core proof")));
            }

            if proof.last().unwrap().public_values.len() != PROOF_MAX_NUM_PVS {
                return Err(SP1VerificationError::InvalidPublicValues);
            }

            let public_values: &PublicValues<[_; 4], [_; 3], [_; 4], _> =
                proof.last().unwrap().public_values.as_slice().borrow();

            if !status_code.is_accepted_code(public_values.exit_code.as_canonical_u32()) {
                return Err(SP1VerificationError::UnexpectedExitCode(
                    public_values.exit_code.as_canonical_u32(),
                ));
            }

            // Get the committed value digest bytes.
            let committed_value_digest_bytes = public_values
                .committed_value_digest
                .iter()
                .flat_map(|w| w.iter().map(|x| x.as_canonical_u32() as u8))
                .collect_vec();

            // Make sure the committed value digest matches the public values hash.
            // It is computationally infeasible to find two distinct inputs, one processed with
            // SHA256 and the other with Blake3, that yield the same hash value.
            if committed_value_digest_bytes != bundle.public_values.hash()
                && committed_value_digest_bytes != bundle.public_values.blake3_hash()
            {
                tracing::error!("committed value digest doesnt match");
                return Err(SP1VerificationError::InvalidPublicValues);
            }
        }
        SP1Proof::Compressed(proof) => {
            if proof.proof.public_values.len() != PROOF_MAX_NUM_PVS {
                return Err(SP1VerificationError::InvalidPublicValues);
            }

            let public_values: &RecursionPublicValues<_> =
                proof.proof.public_values.as_slice().borrow();

            if !status_code.is_accepted_code(public_values.exit_code.as_canonical_u32()) {
                return Err(SP1VerificationError::UnexpectedExitCode(
                    public_values.exit_code.as_canonical_u32(),
                ));
            }

            // Get the committed value digest bytes.
            let committed_value_digest_bytes = public_values
                .committed_value_digest
                .iter()
                .flat_map(|w| w.iter().map(|x| x.as_canonical_u32() as u8))
                .collect_vec();

            // Make sure the committed value digest matches the public values hash.
            // It is computationally infeasible to find two distinct inputs, one processed with
            // SHA256 and the other with Blake3, that yield the same hash value.
            if committed_value_digest_bytes != bundle.public_values.hash()
                && committed_value_digest_bytes != bundle.public_values.blake3_hash()
            {
                return Err(SP1VerificationError::InvalidPublicValues);
            }
        }
        SP1Proof::Plonk(proof) => {
            let exit_code = BigUint::from_str(&proof.public_inputs[2])
                .map_err(|e| SP1VerificationError::Plonk(anyhow::anyhow!(e)))?;

            let exit_code_u32 =
                u32::try_from(&exit_code).map_err(|_| SP1VerificationError::InvalidPublicValues)?;

            if !status_code.is_accepted_code(exit_code_u32) {
                return Err(SP1VerificationError::UnexpectedExitCode(exit_code_u32));
            }

            let public_values_hash = BigUint::from_str(&proof.public_inputs[1])
                .map_err(|e| SP1VerificationError::Plonk(anyhow::anyhow!(e)))?;
            verify_public_values(&bundle.public_values, public_values_hash)
                .map_err(SP1VerificationError::Plonk)?;
        }

        SP1Proof::Groth16(proof) => {
            let exit_code = BigUint::from_str(&proof.public_inputs[2])
                .map_err(|e| SP1VerificationError::Plonk(anyhow::anyhow!(e)))?;

            let exit_code_u32 =
                u32::try_from(&exit_code).map_err(|_| SP1VerificationError::InvalidPublicValues)?;

            if !status_code.is_accepted_code(exit_code_u32) {
                return Err(SP1VerificationError::UnexpectedExitCode(exit_code_u32));
            }

            let public_values_hash = BigUint::from_str(&proof.public_inputs[1])
                .map_err(|e| SP1VerificationError::Groth16(anyhow::anyhow!(e)))?;
            verify_public_values(&bundle.public_values, public_values_hash)
                .map_err(SP1VerificationError::Groth16)?;
        }
    }
    node.verify(vkey, &bundle.proof).map_err(|e| match bundle.proof {
        SP1Proof::Core(_) => SP1VerificationError::Core(e),
        SP1Proof::Compressed(_) => SP1VerificationError::Recursion(e),
        SP1Proof::Plonk(_) => SP1VerificationError::Plonk(e),
        SP1Proof::Groth16(_) => SP1VerificationError::Groth16(e),
    })
}
