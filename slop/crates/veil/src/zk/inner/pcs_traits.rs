//! Abstract PCS (Polynomial Commitment Scheme) traits for dependency inversion.
//!
//! These traits allow zk-builder to work with any PCS implementation without
//! directly depending on specific PCS crates. Crates like zk-stacked-pcs can
//! implement these traits to integrate with the zk-builder constraint system.

use std::fmt::Debug;

use slop_alloc::CpuBackend;
use slop_multilinear::Mle;
use thiserror::Error;

use super::transcript::PcsEvalClaim;
use super::{
    ProverValue, VerifierValue, ZkIopCtx, ZkMerkleizer, ZkProverContext, ZkVerificationContext,
};

/// Error type for PCS commitment failures.
#[derive(Debug, Clone, Error)]
pub enum ZkPcsCommitmentError {
    /// The PCS commitment failed.
    #[error("PCS commitment failed: {0}")]
    CommitmentFailed(String),
}

/// Error type for PCS verification failures.
#[derive(Debug, Clone, Error)]
pub enum ZkPcsVerificationError {
    /// The PCS proof verification failed.
    #[error("PCS proof verification failed: {0}")]
    VerificationFailed(String),
}

/// Trait for PCS provers that generate evaluation proofs.
///
/// Implementations of this trait can generate zero-knowledge proofs
/// for MLE (Multilinear Extension) evaluations that integrate with
/// the zk-builder constraint system.
///
/// # Type Parameters
/// * `GC` - The ZK IOP context type (e.g., `KoalaBearDegree4Duplex`)
/// * `MK` - The merkleizer type used by the inner constraint prover
pub trait ZkPcsProver<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> {
    /// The prover data type returned from committing an MLE.
    ///
    /// This typically contains information needed to open the commitment
    /// at arbitrary points, such as the original polynomial coefficients
    /// or Merkle tree authentication paths.
    type ProverData;

    /// The serializable proof type that can be included in the overall proof.
    ///
    /// This proof will be sent to the verifier and should contain all
    /// information needed to verify the evaluation claim.
    type Proof;

    /// Commits to an MLE by stacking it internally.
    ///
    /// This method stacks the flat MLE into `2^log_stacking_height` columns,
    /// then generates a commitment and returns the commitment digest along with
    /// prover data needed for later evaluation proofs.
    ///
    /// # Arguments
    /// * `mle` - The flat (unstacked) MLE to commit to
    /// * `log_stacking_height` - Log2 of the number of columns to stack into
    /// * `rng` - Cryptographically secure random number generator
    ///
    /// # Returns
    /// A tuple of (commitment digest, prover data) or an error.
    fn commit_mle<RNG: rand::CryptoRng + rand::Rng>(
        &self,
        mle: Mle<GC::F, CpuBackend>,
        log_stacking_height: usize,
        rng: &mut RNG,
    ) -> Result<(GC::Digest, Self::ProverData), ZkPcsCommitmentError>
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::F>;

    /// Generates an evaluation proof for a single claim on one commitment.
    ///
    /// # Arguments
    /// * `ctx` - The prover constraint context
    /// * `claim` - The evaluation claim to prove
    ///
    /// # Returns
    /// A proof for the claim.
    #[allow(clippy::type_complexity)]
    fn prove_eval(
        &self,
        ctx: &mut ZkProverContext<GC, MK, Self::ProverData>,
        claim: PcsEvalClaim<GC::EF, ProverValue<GC, MK, Self::ProverData>>,
    ) -> Self::Proof;
}

/// Trait for PCS verifiers that verify evaluation proofs.
///
/// Implementations verify zero-knowledge proofs for MLE evaluations
/// and build the corresponding constraints on the verification context.
///
/// # Type Parameters
/// * `GC` - The ZK IOP context type
pub trait ZkPcsVerifier<GC: ZkIopCtx> {
    /// The proof type to verify.
    ///
    /// This should match the `Proof` type from the corresponding `ZkPcsProver`.
    type Proof;

    /// Verifies an evaluation proof for a single claim on one commitment.
    ///
    /// # Arguments
    /// * `ctx` - The verifier constraint context
    /// * `claim` - The evaluation claim to verify
    /// * `proof` - The proof to verify
    ///
    /// # Returns
    /// `Ok(())` if verification succeeds, or an error describing the failure.
    #[allow(clippy::type_complexity)]
    fn verify_eval(
        &self,
        ctx: &mut ZkVerificationContext<GC, Self::Proof>,
        claim: PcsEvalClaim<GC::EF, VerifierValue<GC, Self::Proof>>,
        proof: &Self::Proof,
    ) -> Result<(), ZkPcsVerificationError>;
}
