//! no-PCS convenience helpers: everything needed to run veil on pure constraint proofs (no MLE
//! commitments or eval openings)].
//!
//! The null objects [`NoPcsProver`] / [`NoPcsVerifier`] satisfy the PCS traits without doing
//! anything: the contexts hold an `Option` of their PCS machinery and report a `NoPcsProver` /
//! `NoPcsVerifier` error on `None` before reaching these types' methods, so the methods are never
//! called. The `*_without_pcs` constructors and finalizers are thin conveniences that fix the
//! `Option` to `None` (and, on the prover side, the config to [`NoPcsConfig`]) so callers don't
//! need turbofish annotations.
//!
//! Note that the null objects deliberately do **not** implement the stacked-PCS `Sealed` marker,
//! which is what lets their direct [`ZkPcsProver`]/[`ZkPcsVerifier`] impls coexist with the
//! blanket impls in [`crate::zk::stacked_pcs`] without a coherence conflict.

use std::convert::Infallible;
use std::marker::PhantomData;

use rand::distributions::{Distribution, Standard};
use rand::{CryptoRng, Rng};
use slop_alloc::CpuBackend;
use slop_commit::{Message, Rounds};
use slop_merkle_tree::TensorCsProver;
use slop_multilinear::{Mle, Point};

use crate::zk::inner::{
    MleCommitmentIndex, ProverValue, VerifierValue, ZkMerkleizer, ZkPcsCommitmentError,
    ZkPcsProver, ZkPcsVerificationError, ZkPcsVerifier, ZkProveError, ZkProverContext,
    ZkVerificationContext, ZkVerifierError,
};
use crate::zk::{PcsProverConfig, ZkIopCtx, ZkProof, ZkProverCtx, ZkVerifierCtx};

// ============================================================================
// Prover side
// ============================================================================

/// A no-op PCS prover for when no PCS is needed.
///
/// This type is used as a default when calling `prove` without PCS support.
/// It produces no proofs and panics if actually asked to prove anything.
#[derive(Clone, Copy, Debug)]
pub struct NoPcsProver;

impl<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> ZkPcsProver<GC, MK> for NoPcsProver {
    type Proof = ();
    type ProverData = ();
    type ProveError = Infallible;

    fn num_encoding_variables(&self) -> u32 {
        panic!("NoPcsProver::num_encoding_variables should never be called")
    }

    fn commit_mle<RNG: CryptoRng + Rng>(
        &self,
        _mle: Message<Mle<GC::F, CpuBackend>>,
        _rng: &mut RNG,
    ) -> Result<(GC::Digest, Self::ProverData), ZkPcsCommitmentError>
    where
        Standard: Distribution<GC::F>,
    {
        panic!("NoPcsProver::commit_mle should never be called")
    }

    #[allow(clippy::type_complexity)]
    fn prove_multi_eval(
        &self,
        _ctx: &mut ZkProverContext<GC, MK, ()>,
        _commitment_indices: Rounds<MleCommitmentIndex>,
        _reduced_point: &Point<GC::EF>,
    ) -> Result<((), Rounds<Vec<ProverValue<GC, MK, ()>>>), Self::ProveError> {
        panic!("NoPcsProver::prove_multi_eval should never be called")
    }
}

/// A `PcsProverConfig` for proofs that don't use a PCS (pure constraint proofs).
pub struct NoPcsConfig<MK>(PhantomData<MK>);

impl<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> PcsProverConfig<GC> for NoPcsConfig<MK> {
    type Merkelizer = MK;
    type PcsProver = NoPcsProver;
}

impl<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> ZkProverCtx<GC, NoPcsConfig<MK>> {
    /// Generates a proof without PCS support. Returns
    /// [`ZkProveError::NoPcsProver`] if PCS eval claims were registered.
    ///
    /// Identical to [`Self::prove`]; under [`NoPcsConfig`] the generic error type already
    /// specializes to the no-PCS one (`Infallible` PCS error).
    #[allow(clippy::type_complexity)]
    pub fn prove_without_pcs<RNG: CryptoRng + Rng>(
        self,
        rng: &mut RNG,
    ) -> Result<
        ZkProof<GC>,
        ZkProveError<Infallible, <MK as TensorCsProver<GC, CpuBackend>>::ProverError>,
    >
    where
        Standard: Distribution<GC::EF>,
    {
        self.prove(rng)
    }

    /// Initializes a no-PCS prover with both linear and multiplicative constraints.
    pub fn initialize_without_pcs<RNG: CryptoRng + Rng>(
        length: usize,
        rng: &mut RNG,
    ) -> Result<Self, <MK as TensorCsProver<GC, CpuBackend>>::ProverError>
    where
        Standard: Distribution<GC::EF>,
    {
        Self::initialize(length, rng, None)
    }

    /// Initializes a no-PCS prover with only linear constraints.
    pub fn initialize_without_pcs_only_lin<RNG: CryptoRng + Rng>(
        length: usize,
        rng: &mut RNG,
    ) -> Result<Self, <MK as TensorCsProver<GC, CpuBackend>>::ProverError>
    where
        Standard: Distribution<GC::EF>,
    {
        Self::initialize_only_lin_constraints(length, rng, None)
    }
}

impl<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> ZkProverContext<GC, MK, ()> {
    /// Convenience method to generate a proof without PCS support.
    ///
    /// Identical to [`Self::prove`] for a PCS-free context: with no MLE-eval openings, no PCS
    /// proofs are collected. Kept for symmetry with the verifier's `verify_without_pcs`.
    pub fn prove_without_pcs<RNG: CryptoRng + Rng>(
        self,
        rng: &mut RNG,
    ) -> Result<ZkProof<GC>, ZkProveError<Infallible, MK::ProverError>>
    where
        Standard: Distribution<GC::EF>,
    {
        self.prove(rng)
    }
}

// ============================================================================
// Verifier side
// ============================================================================

/// A no-op PCS verifier for proofs without PCS openings — the verifier-side counterpart of
/// [`NoPcsProver`].
#[derive(Clone, Copy, Debug)]
pub struct NoPcsVerifier;

impl<GC: ZkIopCtx> ZkPcsVerifier<GC> for NoPcsVerifier {
    type Proof = ();

    fn num_encoding_variables(&self) -> u32 {
        panic!("NoPcsVerifier::num_encoding_variables should never be called")
    }

    fn verify_multi_eval(
        &self,
        _ctx: &mut ZkVerificationContext<GC>,
        _commitment_indices: Rounds<MleCommitmentIndex>,
        _reduced_point: &Point<GC::EF>,
        _proof: &(),
    ) -> Result<Rounds<Vec<VerifierValue<GC>>>, ZkPcsVerificationError> {
        panic!("NoPcsVerifier::verify_multi_eval should never be called")
    }
}

impl<GC: ZkIopCtx> ZkVerifierCtx<GC, NoPcsVerifier> {
    /// Initializes a verifier for a proof without PCS openings (pure constraint proofs) — the
    /// verifier-side counterpart of [`NoPcsConfig`]. Any `assert_mle_*` claim will fail with
    /// `ZkVerifierError::NoPcsVerifier`.
    pub fn init_without_pcs(proof: ZkProof<GC>) -> Self {
        Self::init(proof, None)
    }
}

impl<GC: ZkIopCtx> ZkVerificationContext<GC> {
    /// Convenience method to verify a proof without PCS support.
    ///
    /// Identical to [`Self::verify`]: with no MLE-eval openings there are no PCS proofs to consume.
    /// Kept for symmetry with the prover's `prove_without_pcs`.
    ///
    /// # Errors
    /// Returns [`ZkVerifierError::PcsProofCountMismatch`] if the proof carries any PCS proofs that
    /// were never consumed by an opening.
    pub fn verify_without_pcs(self) -> Result<(), ZkVerifierError> {
        self.verify()
    }
}
