//! Abstract PCS (Polynomial Commitment Scheme) traits for dependency inversion.
//!
//! These traits let the ZK constraint contexts ([`ZkProverContext`] /
//! [`ZkVerificationContext`]) work with any polynomial-commitment scheme without
//! depending on its concrete types. The stacked-PCS backend in
//! [`crate::zk::stacked_pcs`] implements them to integrate with the constraint system.

use std::fmt::Debug;

use slop_alloc::CpuBackend;
use slop_commit::{Message, Rounds};
use slop_multilinear::Mle;
use thiserror::Error;

use super::transcript::{MleCommitmentIndex, Point};
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
    /// The PCS opening-proof wire format this prover produces. Threaded explicitly (rather than
    /// fixed on `GC`) so a single context type can be used with any PCS.
    type Proof: Clone + serde::Serialize + serde::de::DeserializeOwned;

    /// The prover data type returned from committing an MLE.
    ///
    /// This typically contains information needed to open the commitment
    /// at arbitrary points, such as the original polynomial coefficients
    /// or Merkle tree authentication paths.
    type ProverData: Clone;

    /// Error type returned by [`Self::prove_multi_eval`]. Concrete impls thread their
    /// own typed error here so a top-level `prove()` failure carries the original
    /// PCS error rather than a stringified copy.
    type ProveError: std::error::Error + 'static;

    /// The fixed number of encoding variables (log of the stacking height) this PCS
    /// was configured with. Every committed MLE is stacked into a tensor whose columns
    /// are polynomials over this many variables, so `log_num_polynomials` for any MLE
    /// is `mle.num_variables() - num_encoding_variables`.
    fn num_encoding_variables(&self) -> u32;

    /// Commits to a **pre-stacked** MLE.
    ///
    /// `mle[0]` is the block-column tensor `[2^num_encoding_variables, num_columns]` (column `ℓ` is
    /// the consecutive block `f_ℓ`), as produced by [`slop_stacked::stack_multilinear`] or held
    /// directly by a column-major producer (e.g. jagged). The number of stacked columns and the
    /// encoding width are read from the tensor's shape; no transpose is performed here. The MLE is
    /// passed as a [`Message`] so its buffer can be read without cloning or consuming the caller's
    /// data.
    ///
    /// # Arguments
    /// * `mle` — the pre-stacked block-column MLE to commit to.
    /// * `rng` — cryptographically secure random number generator.
    ///
    /// # Returns
    /// A tuple of (commitment digest, prover data) or an error.
    fn commit_mle<RNG: rand::CryptoRng + rand::Rng>(
        &self,
        mle: Message<Mle<GC::F, CpuBackend>>,
        rng: &mut RNG,
    ) -> Result<(GC::Digest, Self::ProverData), ZkPcsCommitmentError>
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::F>;

    /// Opens one or more commitments at the (already reduced) `reduced_point`, proving and
    /// discharging the PCS-internal consistency, and returns the proof together with the
    /// per-commitment **column sub-evaluations**. The caller is responsible for asserting how those
    /// columns combine into each commitment's claimed evaluation (the decomposition).
    ///
    /// # Returns
    /// `(proof, columns)` where `columns` is a [`Rounds`] with one entry per commitment (in
    /// `commitment_indices` order): `columns[j]` are commitment `j`'s data-column sub-evaluation
    /// expressions. Returns [`Self::ProveError`] on failure.
    #[allow(clippy::type_complexity)]
    fn prove_multi_eval(
        &self,
        ctx: &mut ZkProverContext<GC, MK, Self::ProverData, Self::Proof>,
        commitment_indices: Rounds<MleCommitmentIndex>,
        reduced_point: &Point<GC::EF>,
    ) -> Result<
        (Self::Proof, Rounds<Vec<ProverValue<GC, MK, Self::ProverData, Self::Proof>>>),
        Self::ProveError,
    >;
}

/// Trait for PCS verifiers that verify evaluation proofs.
///
/// Implementations verify zero-knowledge proofs for MLE evaluations
/// and build the corresponding constraints on the verification context.
///
/// The proof type verified is the context's [`ZkIopCtx::PcsProof`] — the wire format the
/// prover and verifier agree on through `GC`.
///
/// # Type Parameters
/// * `GC` - The ZK IOP context type
pub trait ZkPcsVerifier<GC: ZkIopCtx> {
    /// The PCS opening-proof wire format this verifier consumes (matches the prover's
    /// [`ZkPcsProver::Proof`]).
    type Proof: Clone;

    /// The fixed number of encoding variables (log of the stacking height) this PCS
    /// was configured with. Used to recover `log_num_polynomials` from an oracle's
    /// total number of variables: `log_num_polynomials = num_variables - num_encoding_variables`.
    fn num_encoding_variables(&self) -> u32;

    /// Verifies a (possibly batched) opening of one or more commitments at the (already reduced)
    /// `reduced_point`, discharging the PCS-internal consistency, and returns the per-commitment
    /// **column sub-evaluations**. The caller asserts how those columns combine into each
    /// commitment's claimed evaluation (the decomposition).
    ///
    /// # Returns
    /// `Ok(columns)` where `columns` is a [`Rounds`] with one entry per commitment (in
    /// `commitment_indices` order): `columns[j]` are commitment `j`'s data-column sub-evaluation
    /// expressions. Returns an error describing the failure otherwise.
    #[allow(clippy::type_complexity)]
    fn verify_multi_eval(
        &self,
        ctx: &mut ZkVerificationContext<GC, Self::Proof>,
        commitment_indices: Rounds<MleCommitmentIndex>,
        reduced_point: &Point<GC::EF>,
        proof: &Self::Proof,
    ) -> Result<Rounds<Vec<VerifierValue<GC, Self::Proof>>>, ZkPcsVerificationError>;
}
