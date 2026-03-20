//! Abstract PCS (Polynomial Commitment Scheme) traits for dependency inversion.
//!
//! These traits allow zk-builder to work with any PCS implementation without
//! directly depending on specific PCS crates. Crates like zk-stacked-pcs can
//! implement these traits to integrate with the zk-builder constraint system.

use std::fmt::Debug;

use slop_alloc::CpuBackend;
use slop_multilinear::Mle;
use thiserror::Error;

use super::transcript::PcsMultiEvalClaim;
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

    /// Commits to an MLE by stacking it internally.
    ///
    /// The flat MLE is stacked into a tensor with `2^log_num_polynomials` columns,
    /// each over `num_encoding_variables = mle.num_variables() - log_num_polynomials`
    /// variables.
    ///
    /// # Arguments
    /// * `mle` — the flat (unstacked) MLE to commit to.
    /// * `log_num_polynomials` — log2 of the number of stacked polynomials (tensor height).
    /// * `rng` — cryptographically secure random number generator.
    ///
    /// # Returns
    /// A tuple of (commitment digest, prover data) or an error.
    fn commit_mle<RNG: rand::CryptoRng + rand::Rng>(
        &self,
        mle: Mle<GC::F, CpuBackend>,
        log_num_polynomials: usize,
        rng: &mut RNG,
    ) -> Result<(GC::Digest, Self::ProverData), ZkPcsCommitmentError>
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::F>;

    /// Generates a (possibly batched) evaluation proof for one or more commitments
    /// at the same point.
    ///
    /// # Arguments
    /// * `ctx` - The prover constraint context
    /// * `claim` - The evaluation claim (may contain one or multiple commitments)
    ///
    /// # Returns
    /// A single proof covering all commitments in the claim.
    #[allow(clippy::type_complexity)]
    fn prove_multi_eval(
        &self,
        ctx: &mut ZkProverContext<GC, MK, Self::ProverData>,
        claim: PcsMultiEvalClaim<GC::EF, ProverValue<GC, MK, Self::ProverData>>,
    ) -> GC::PcsProof;
}

/// Trait for PCS verifiers that verify evaluation proofs.
///
/// Implementations verify zero-knowledge proofs for MLE evaluations
/// and build the corresponding constraints on the verification context.
///
/// The `Proof` associated type must equal `GC::PcsProof` when used with
/// [`ZkVerificationContext::verify`].
///
/// # Type Parameters
/// * `GC` - The ZK IOP context type
pub trait ZkPcsVerifier<GC: ZkIopCtx> {
    /// The proof type to verify. Must equal `GC::PcsProof` in practice.
    type Proof;

    /// Verifies a (possibly batched) evaluation proof for one or more commitments
    /// at the same point.
    ///
    /// # Arguments
    /// * `ctx` - The verifier constraint context
    /// * `claim` - The evaluation claim (may contain one or multiple commitments)
    /// * `proof` - The proof to verify
    ///
    /// # Returns
    /// `Ok(())` if verification succeeds, or an error describing the failure.
    #[allow(clippy::type_complexity)]
    fn verify_multi_eval(
        &self,
        ctx: &mut ZkVerificationContext<GC>,
        claim: PcsMultiEvalClaim<GC::EF, VerifierValue<GC>>,
        proof: &Self::Proof,
    ) -> Result<(), ZkPcsVerificationError>;
}
