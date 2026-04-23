use std::cell::RefMut;
use std::marker::PhantomData;

use slop_algebra::Dorroh;
use slop_alloc::CpuBackend;
use slop_challenger::{FieldChallenger, IopCtx};
use slop_multilinear::Point;
use thiserror::Error;

use crate::compiler::{ConstraintCtx, SendingCtx};
use crate::zk::inner::{
    ConstraintContextInnerExt, NoPcsProver, ProverValue, ZkPcsProver, ZkProverContext,
};
use crate::zk::verifier_ctx::MleCommit;
use crate::zk::{ZkIopCtx, ZkProof};

/// Auto-implemented trait that bundles the merkle commitment bounds needed by prover code.
///
/// Any type implementing `TensorCsProver + ComputeTcsOpenings + Default` automatically
/// satisfies this trait. Pass it as a separate generic `MK: ZkMerkleizer<GC>` on
/// prover-side structs and functions instead of baking it into `ZkIopCtx`.
pub trait ZkMerkleizer<GC: IopCtx>:
    slop_merkle_tree::TensorCsProver<GC, CpuBackend>
    + slop_merkle_tree::ComputeTcsOpenings<GC, CpuBackend>
    + Default
{
}

impl<MK, GC: IopCtx> ZkMerkleizer<GC> for MK where
    MK: slop_merkle_tree::TensorCsProver<GC, CpuBackend>
        + slop_merkle_tree::ComputeTcsOpenings<GC, CpuBackend>
        + Default
{
}

/// Type alias for the prover data produced by a `ZkMerkleizer`.
pub type MerkleProverData<GC, MK> =
    <MK as slop_merkle_tree::TensorCsProver<GC, CpuBackend>>::ProverData;

pub trait PcsProverConfig<GC: ZkIopCtx> {
    type Merkelizer: ZkMerkleizer<GC>;
    type PcsProverData: Clone;
    type PcsProver: ZkPcsProver<GC, Self::Merkelizer, ProverData = Self::PcsProverData>;
}

/// A `PcsProverConfig` for proofs that don't use a PCS (pure constraint proofs).
pub struct NoPcsConfig<MK>(PhantomData<MK>);

impl<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> PcsProverConfig<GC> for NoPcsConfig<MK> {
    type Merkelizer = MK;
    type PcsProverData = ();
    type PcsProver = NoPcsProver;
}

/// An abstract representation of a prover transcript extension field element.
///
/// Either a concrete field constant (`Dorroh::Constant`) or an opaque expression index
/// into the prover transcript (`Dorroh::Element`).
#[allow(type_alias_bounds)]
pub type ProverTranscriptElement<GC: ZkIopCtx, PC: PcsProverConfig<GC>> =
    Dorroh<GC::EF, ProverValue<GC, PC::Merkelizer, PC::PcsProverData>>;

pub struct ZkProverCtx<GC: ZkIopCtx, PC: PcsProverConfig<GC>> {
    inner: ZkProverContext<GC, PC::Merkelizer, PC::PcsProverData>,
    pcs_prover: Option<PC::PcsProver>,
}

impl<GC: ZkIopCtx, PC: PcsProverConfig<GC>> ZkProverCtx<GC, PC> {
    fn new(
        inner: ZkProverContext<GC, PC::Merkelizer, PC::PcsProverData>,
        pcs_prover: Option<PC::PcsProver>,
    ) -> Self {
        Self { inner, pcs_prover }
    }

    fn into_inner(self) -> ZkProverContext<GC, PC::Merkelizer, PC::PcsProverData> {
        self.inner
    }
}

// ============================================================================
// Conversion helper: ProverTranscriptElement → ProverValue
// ============================================================================

fn into_prover_value<GC: ZkIopCtx, PC: PcsProverConfig<GC>>(
    elem: ProverTranscriptElement<GC, PC>,
    ctx: &mut ZkProverContext<GC, PC::Merkelizer, PC::PcsProverData>,
) -> ProverValue<GC, PC::Merkelizer, PC::PcsProverData> {
    match elem {
        Dorroh::Constant(f) => ctx.cst(f),
        Dorroh::Element(e) => e,
    }
}

// ============================================================================
// ConstraintCtx impl
// ============================================================================

impl<GC: ZkIopCtx, PC: PcsProverConfig<GC>> ConstraintCtx for ZkProverCtx<GC, PC> {
    type Field = GC::F;
    type Extension = GC::EF;
    type Expr = ProverTranscriptElement<GC, PC>;
    type Challenge = GC::EF;
    type MleOracle = MleCommit;
    type AssertError = std::convert::Infallible;

    fn assert_zero(
        &mut self,
        expr: ProverTranscriptElement<GC, PC>,
    ) -> Result<(), Self::AssertError> {
        let idx = into_prover_value::<GC, PC>(expr, &mut self.inner);
        self.inner.assert_zero(idx);
        Ok(())
    }

    fn assert_a_times_b_equals_c(
        &mut self,
        a: ProverTranscriptElement<GC, PC>,
        b: ProverTranscriptElement<GC, PC>,
        c: ProverTranscriptElement<GC, PC>,
    ) -> Result<(), Self::AssertError> {
        let ai = into_prover_value::<GC, PC>(a, &mut self.inner);
        let bi = into_prover_value::<GC, PC>(b, &mut self.inner);
        let ci = into_prover_value::<GC, PC>(c, &mut self.inner);
        self.inner.assert_a_times_b_equals_c(ai, bi, ci);
        Ok(())
    }

    fn assert_mle_multi_eval(
        &mut self,
        claims: Vec<(MleCommit, ProverTranscriptElement<GC, PC>)>,
        point: Point<GC::EF>,
    ) {
        let inner_claims: Vec<_> = claims
            .into_iter()
            .map(|(oracle, eval_expr)| {
                let eval_idx = into_prover_value::<GC, PC>(eval_expr, &mut self.inner);
                (oracle.inner, eval_idx)
            })
            .collect();
        self.inner.assert_mle_multi_eval(inner_claims, point);
    }
}

// ============================================================================
// SendingCtx impl
// ============================================================================

impl<GC: ZkIopCtx, PC: PcsProverConfig<GC>> SendingCtx for ZkProverCtx<GC, PC> {
    type CommitError = PcsCommitError;

    fn send_value(&mut self, value: GC::EF) -> ProverTranscriptElement<GC, PC> {
        Dorroh::Element(self.inner.add_value(value))
    }

    fn send_values(&mut self, values: &[GC::EF]) -> Vec<ProverTranscriptElement<GC, PC>> {
        self.inner.add_values(values).into_iter().map(Dorroh::Element).collect()
    }

    fn to_value(&self, expr: &ProverTranscriptElement<GC, PC>) -> GC::EF {
        match expr {
            Dorroh::Constant(f) => *f,
            Dorroh::Element(e) => e.value(),
        }
    }

    fn sample(&mut self) -> GC::EF {
        self.inner.challenger().sample_ext_element()
    }

    fn commit_mle<RNG: rand::CryptoRng + rand::Rng>(
        &mut self,
        mle: slop_multilinear::Mle<GC::F>,
        log_num_polynomials: u32,
        rng: &mut RNG,
    ) -> Result<MleCommit, PcsCommitError>
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::F>,
    {
        let pcs_prover = self.pcs_prover.as_ref().ok_or(PcsCommitError::NoPcsProver)?;
        let commit = self
            .inner
            .commit_mle(mle, log_num_polynomials as usize, pcs_prover, rng)
            .map(|idx| MleCommit { inner: idx })?;
        Ok(commit)
    }
}

// ============================================================================
// Prover-specific methods
// ============================================================================

#[derive(Debug, Clone, Error)]
pub enum PcsCommitError {
    #[error("commitment failed, {0}")]
    Failed(#[from] super::inner::ZkPcsCommitmentError),
    #[error("Context not initialized with Pcs Prover")]
    NoPcsProver,
}

impl<GC: ZkIopCtx, PC: PcsProverConfig<GC>> ZkProverCtx<GC, PC> {
    /// Access the challenger directly for Fiat-Shamir operations.
    pub fn challenger(&mut self) -> RefMut<'_, GC::Challenger> {
        self.inner.challenger()
    }

    /// Commits to a flat MLE and registers it in the context.
    ///
    /// The MLE is internally stacked into a tensor with `2^log_num_polynomials` columns.
    /// The number of encoding variables is inferred as
    /// `mle.num_variables() - log_num_polynomials`.
    ///
    /// # Arguments
    /// * `mle` — the flat (unstacked) multilinear extension to commit to, with
    ///   `num_encoding_variables + log_num_polynomials` total variables.
    /// * `log_num_polynomials` — log2 of the number of stacked polynomials (tensor height).
    ///   The inferred `num_encoding_variables` must match the value passed to
    ///   [`initialize_zk_prover_and_verifier`](crate::zk::stacked_pcs::initialize_zk_prover_and_verifier)
    ///   when the PCS was set up.
    /// * `rng` — cryptographically secure random number generator.
    pub fn commit_mle<RNG>(
        &mut self,
        mle: slop_multilinear::Mle<GC::F, slop_alloc::CpuBackend>,
        log_num_polynomials: u32,
        rng: &mut RNG,
    ) -> Result<MleCommit, PcsCommitError>
    where
        RNG: rand::CryptoRng + rand::Rng,
        rand::distributions::Standard: rand::distributions::Distribution<GC::F>,
    {
        let pcs_prover = self.pcs_prover.as_ref().ok_or(PcsCommitError::NoPcsProver)?;
        let commit = self
            .inner
            .commit_mle(mle, log_num_polynomials as usize, pcs_prover, rng)
            .map(|idx| MleCommit { inner: idx })?;
        Ok(commit)
    }

    /// Generates a zero-knowledge proof. Consumes self.
    pub fn prove<RNG: rand::CryptoRng + rand::Rng>(self, rng: &mut RNG) -> ZkProof<GC>
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
    {
        self.inner.prove(rng, self.pcs_prover.as_ref())
    }
}

impl<GC: ZkIopCtx, PC: PcsProverConfig<GC>> ZkProverCtx<GC, PC> {
    /// Initializes a prover that supports both linear and multiplicative constraints.
    pub fn initialize<RNG: rand::CryptoRng + rand::Rng>(
        length: usize,
        rng: &mut RNG,
        pcs_prover: Option<PC::PcsProver>,
    ) -> Self
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
    {
        Self { inner: ZkProverContext::initialize(length, rng), pcs_prover }
    }

    /// Initializes a prover that supports only linear constraints.
    pub fn initialize_only_lin_constraints<RNG: rand::CryptoRng + rand::Rng>(
        length: usize,
        rng: &mut RNG,
        pcs_prover: Option<PC::PcsProver>,
    ) -> Self
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
    {
        Self { inner: ZkProverContext::initialize_only_lin_constraints(length, rng), pcs_prover }
    }
}

// ============================================================================
// No-PCS convenience methods
// ============================================================================

impl<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> ZkProverCtx<GC, NoPcsConfig<MK>> {
    /// Generates a proof without PCS support. Panics if PCS eval claims were registered.
    pub fn prove_without_pcs<RNG: rand::CryptoRng + rand::Rng>(self, rng: &mut RNG) -> ZkProof<GC>
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
    {
        self.inner.prove_without_pcs(rng)
    }

    /// Initializes a no-PCS prover with both linear and multiplicative constraints.
    pub fn initialize_without_pcs<RNG: rand::CryptoRng + rand::Rng>(
        length: usize,
        rng: &mut RNG,
    ) -> Self
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
    {
        Self { inner: ZkProverContext::initialize(length, rng), pcs_prover: None }
    }

    /// Initializes a no-PCS prover with only linear constraints.
    pub fn initialize_without_pcs_only_lin<RNG: rand::CryptoRng + rand::Rng>(
        length: usize,
        rng: &mut RNG,
    ) -> Self
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
    {
        Self {
            inner: ZkProverContext::initialize_only_lin_constraints(length, rng),
            pcs_prover: None,
        }
    }
}
