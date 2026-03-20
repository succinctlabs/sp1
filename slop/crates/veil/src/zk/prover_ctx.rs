use std::cell::RefMut;

use slop_algebra::Dorroh;
use slop_alloc::CpuBackend;
use slop_challenger::{FieldChallenger, IopCtx};
use slop_multilinear::Point;

use crate::compiler::{ConstraintCtx, SendingCtx};
use crate::zk::inner::{ConstraintContextInnerExt, ProverValue, ZkProverContext};
use crate::zk::verifier_ctx::MleCommit;
use crate::zk::ZkIopCtx;

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

/// An abstract representation of a prover transcript extension field element.
///
/// Either a concrete field constant (`Dorroh::Constant`) or an opaque expression index
/// into the prover transcript (`Dorroh::Element`).
#[allow(type_alias_bounds)]
pub type ProverTranscriptElement<GC: ZkIopCtx, MK: ZkMerkleizer<GC>, PD = ()> =
    Dorroh<GC::EF, ProverValue<GC, MK, PD>>;

pub struct ZkProverCtx<GC: ZkIopCtx, MK: ZkMerkleizer<GC>, PD = ()> {
    inner: ZkProverContext<GC, MK, PD>,
}

impl<GC: ZkIopCtx, MK: ZkMerkleizer<GC>, PD> ZkProverCtx<GC, MK, PD> {
    pub fn new(inner: ZkProverContext<GC, MK, PD>) -> Self {
        Self { inner }
    }

    pub fn into_inner(self) -> ZkProverContext<GC, MK, PD> {
        self.inner
    }
}

// ============================================================================
// Conversion helper: ProverTranscriptElement → ProverValue
// ============================================================================

fn into_prover_value<GC: ZkIopCtx, MK: ZkMerkleizer<GC>, PD: Clone>(
    elem: ProverTranscriptElement<GC, MK, PD>,
    ctx: &mut ZkProverContext<GC, MK, PD>,
) -> ProverValue<GC, MK, PD> {
    match elem {
        Dorroh::Constant(f) => ctx.cst(f),
        Dorroh::Element(e) => e,
    }
}

// ============================================================================
// ConstraintCtx impl
// ============================================================================

impl<GC: ZkIopCtx, MK: ZkMerkleizer<GC>, PD: Clone> ConstraintCtx for ZkProverCtx<GC, MK, PD> {
    type Field = GC::F;
    type Extension = GC::EF;
    type Expr = ProverTranscriptElement<GC, MK, PD>;
    type Challenge = GC::EF;
    type MleOracle = MleCommit;

    fn assert_zero(&mut self, expr: ProverTranscriptElement<GC, MK, PD>) {
        let idx = into_prover_value(expr, &mut self.inner);
        self.inner.assert_zero(idx);
    }

    fn assert_a_times_b_equals_c(
        &mut self,
        a: ProverTranscriptElement<GC, MK, PD>,
        b: ProverTranscriptElement<GC, MK, PD>,
        c: ProverTranscriptElement<GC, MK, PD>,
    ) {
        let ai = into_prover_value(a, &mut self.inner);
        let bi = into_prover_value(b, &mut self.inner);
        let ci = into_prover_value(c, &mut self.inner);
        self.inner.assert_a_times_b_equals_c(ai, bi, ci);
    }

    fn assert_mle_eval(
        &mut self,
        oracle: MleCommit,
        point: Point<GC::EF>,
        eval_expr: ProverTranscriptElement<GC, MK, PD>,
    ) {
        let eval_idx = into_prover_value(eval_expr, &mut self.inner);
        self.inner.assert_mle_eval(oracle.inner, point, eval_idx);
    }
}

// ============================================================================
// SendingCtx impl
// ============================================================================

impl<GC: ZkIopCtx, MK: ZkMerkleizer<GC>, PD: Clone> SendingCtx for ZkProverCtx<GC, MK, PD> {
    fn send_value(&mut self, value: GC::EF) -> ProverTranscriptElement<GC, MK, PD> {
        Dorroh::Element(self.inner.add_value(value))
    }

    fn send_values(&mut self, values: &[GC::EF]) -> Vec<ProverTranscriptElement<GC, MK, PD>> {
        self.inner.add_values(values).into_iter().map(Dorroh::Element).collect()
    }

    fn sample(&mut self) -> GC::EF {
        self.inner.challenger().sample_ext_element()
    }
}

// ============================================================================
// Prover-specific methods
// ============================================================================

impl<GC: ZkIopCtx, MK: ZkMerkleizer<GC>, PD: Clone> ZkProverCtx<GC, MK, PD> {
    /// Access the challenger directly for Fiat-Shamir operations.
    pub fn challenger(&mut self) -> RefMut<'_, GC::Challenger> {
        self.inner.challenger()
    }

    /// Commits to a flat MLE and registers it in the context.
    pub fn commit_mle<P, RNG>(
        &mut self,
        mle: slop_multilinear::Mle<GC::F, slop_alloc::CpuBackend>,
        log_stacking_height: usize,
        pcs_prover: &P,
        rng: &mut RNG,
    ) -> Result<MleCommit, super::inner::ZkPcsCommitmentError>
    where
        P: super::inner::ZkPcsProver<GC, MK, ProverData = PD>,
        RNG: rand::CryptoRng + rand::Rng,
        rand::distributions::Standard: rand::distributions::Distribution<GC::F>,
    {
        self.inner
            .commit_mle(mle, log_stacking_height, pcs_prover, rng)
            .map(|idx| MleCommit { inner: idx })
    }

    /// Generates a zero-knowledge proof. Consumes self.
    pub fn prove<RNG, P>(self, rng: &mut RNG, pcs_prover: Option<&P>) -> super::inner::ZkProof<GC>
    where
        RNG: rand::CryptoRng + rand::Rng,
        rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
        P: super::inner::ZkPcsProver<GC, MK, ProverData = PD>,
    {
        self.inner.prove(rng, pcs_prover)
    }
}

impl<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> ZkProverCtx<GC, MK, ()> {
    /// Convenience method to generate a proof without PCS support.
    pub fn prove_without_pcs<RNG: rand::CryptoRng + rand::Rng>(
        self,
        rng: &mut RNG,
    ) -> super::inner::ZkProof<GC>
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
    {
        self.inner.prove_without_pcs(rng)
    }
}

impl<GC: ZkIopCtx, MK: ZkMerkleizer<GC>, PD> ZkProverCtx<GC, MK, PD> {
    /// Initializes a prover that supports both linear and multiplicative constraints.
    pub fn initialize<RNG: rand::CryptoRng + rand::Rng>(length: usize, rng: &mut RNG) -> Self
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
    {
        Self { inner: ZkProverContext::initialize(length, rng) }
    }

    /// Initializes a prover that supports only linear constraints.
    pub fn initialize_only_lin_constraints<RNG: rand::CryptoRng + rand::Rng>(
        length: usize,
        rng: &mut RNG,
    ) -> Self
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
    {
        Self { inner: ZkProverContext::initialize_only_lin_constraints(length, rng) }
    }
}
