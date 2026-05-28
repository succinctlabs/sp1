use parking_lot::MappedMutexGuard;
use std::collections::VecDeque;
use std::marker::PhantomData;

use slop_algebra::Dorroh;
use slop_alloc::CpuBackend;
use slop_challenger::{FieldChallenger, IopCtx};
use slop_multilinear::Point;
use thiserror::Error;

use crate::compiler::{ConstraintCtx, ReadingCtx, SendingCtx, TranscriptReadError};
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
    /// Replay log backing the prover's [`ReadingCtx`] impl (the "new flow").
    ///
    /// During the `SendingCtx` (compute) pass we record, in order, every
    /// transcript handle returned by `send_*`, every sampled challenge, and
    /// every committed oracle. The `ReadingCtx` impl then replays them — purely
    /// from these buffers, *without* touching the challenger — so the prover can
    /// run the exact same unified `verify` body the verifier runs. Leaving the
    /// challenger untouched is what keeps the post-compute Fiat-Shamir state
    /// (used by `prove()` to derive PCS openings) intact.
    replay: ProverReplay<GC, PC>,
}

/// Ordered record/replay buffers for [`ZkProverCtx`]'s [`ReadingCtx`] impl.
///
/// `sent` is a queue consumed *by move* on replay: each transcript handle carries
/// an `Rc` clone of the inner context, so draining the queue as `verify` reads it
/// hands those `Rc`s straight to the constraint builder (which drops them), rather
/// than leaving live clones behind that would force `prove()` to deep-clone the
/// context. `challenges`/`oracles` hold `Copy` data, so they stay simple
/// `Vec` + cursor.
struct ProverReplay<GC: ZkIopCtx, PC: PcsProverConfig<GC>> {
    sent: VecDeque<ProverTranscriptElement<GC, PC>>,
    challenges: Vec<GC::EF>,
    challenge_cursor: usize,
    oracles: Vec<MleCommit>,
    oracle_cursor: usize,
}

impl<GC: ZkIopCtx, PC: PcsProverConfig<GC>> Default for ProverReplay<GC, PC> {
    fn default() -> Self {
        Self {
            sent: VecDeque::new(),
            challenges: Vec::new(),
            challenge_cursor: 0,
            oracles: Vec::new(),
            oracle_cursor: 0,
        }
    }
}

impl<GC: ZkIopCtx, PC: PcsProverConfig<GC>> ZkProverCtx<GC, PC> {
    fn new(
        inner: ZkProverContext<GC, PC::Merkelizer, PC::PcsProverData>,
        pcs_prover: Option<PC::PcsProver>,
    ) -> Self {
        Self { inner, pcs_prover, replay: ProverReplay::default() }
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
        let elem = Dorroh::Element(self.inner.add_value(value));
        self.replay.sent.push_back(elem.clone());
        elem
    }

    fn send_values(&mut self, values: &[GC::EF]) -> Vec<ProverTranscriptElement<GC, PC>> {
        let elems: Vec<_> =
            self.inner.add_values(values).into_iter().map(Dorroh::Element).collect();
        self.replay.sent.extend(elems.iter().cloned());
        elems
    }

    fn to_value(&self, expr: &ProverTranscriptElement<GC, PC>) -> GC::EF {
        match expr {
            Dorroh::Constant(f) => *f,
            Dorroh::Element(e) => e.value(),
        }
    }

    fn sample(&mut self) -> GC::EF {
        let challenge = self.inner.challenger().sample_ext_element();
        self.replay.challenges.push(challenge);
        challenge
    }

    fn commit_mle<RNG: rand::CryptoRng + rand::Rng>(
        &mut self,
        mle: slop_multilinear::Mle<GC::F>,
        rng: &mut RNG,
    ) -> Result<MleCommit, PcsCommitError>
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::F>,
    {
        let pcs_prover = self.pcs_prover.as_ref().ok_or(PcsCommitError::NoPcsProver)?;
        let log_num_polynomials = log_num_polynomials(mle.num_variables(), pcs_prover)?;
        let commit = self
            .inner
            .commit_mle(mle, log_num_polynomials, pcs_prover, rng)
            .map(|idx| MleCommit { inner: idx })?;
        self.replay.oracles.push(commit);
        Ok(commit)
    }
}

/// Recovers `log_num_polynomials` from the MLE's total number of variables and the PCS's
/// fixed `num_encoding_variables`. Errors if the MLE is too small for the PCS.
fn log_num_polynomials<GC: ZkIopCtx, MK: ZkMerkleizer<GC>, PD>(
    mle_num_variables: u32,
    pcs_prover: &impl ZkPcsProver<GC, MK, ProverData = PD>,
) -> Result<usize, PcsCommitError> {
    let num_encoding_variables = pcs_prover.num_encoding_variables();
    let log_num_polynomials = mle_num_variables.checked_sub(num_encoding_variables).ok_or(
        PcsCommitError::MleTooSmall { num_variables: mle_num_variables, num_encoding_variables },
    )?;
    Ok(log_num_polynomials as usize)
}

// ============================================================================
// ReadingCtx impl (prototype, "new flow")
// ============================================================================
//
// Pure record/replay over the buffers populated during the `SendingCtx` pass.
// Crucially, none of these methods touch the challenger: challenges are replayed
// from `replay.challenges` rather than re-sampled, so the prover's Fiat-Shamir
// state (already advanced to its final value by the compute pass) is left exactly
// where `prove()` needs it for PCS-opening derivation.

impl<GC: ZkIopCtx, PC: PcsProverConfig<GC>> ReadingCtx for ZkProverCtx<GC, PC> {
    fn read_exact(&mut self, buf: &mut [Self::Expr]) -> Result<(), TranscriptReadError> {
        // Atomic all-or-nothing: a correct prove/verify mirror never under-fills,
        // but bail before mutating the queue if it would.
        if self.replay.sent.len() < buf.len() {
            return Err(TranscriptReadError::TranscriptExhausted);
        }
        for b in buf.iter_mut() {
            *b = self.replay.sent.pop_front().expect("length checked above");
        }
        Ok(())
    }

    fn read_oracle(&mut self, _num_variables: u32) -> Option<MleCommit> {
        let oracle = self.replay.oracles.get(self.replay.oracle_cursor).copied()?;
        self.replay.oracle_cursor += 1;
        Some(oracle)
    }

    fn sample(&mut self) -> GC::EF {
        let challenge = self.replay.challenges[self.replay.challenge_cursor];
        self.replay.challenge_cursor += 1;
        challenge
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
    #[error(
        "MLE has {num_variables} variables, fewer than the PCS's \
         {num_encoding_variables} encoding variables"
    )]
    MleTooSmall { num_variables: u32, num_encoding_variables: u32 },
}

impl<GC: ZkIopCtx, PC: PcsProverConfig<GC>> ZkProverCtx<GC, PC> {
    /// Access the challenger directly for Fiat-Shamir operations.
    pub fn challenger(&mut self) -> MappedMutexGuard<'_, GC::Challenger> {
        self.inner.challenger()
    }

    /// Commits to a flat MLE and registers it in the context.
    ///
    /// The MLE is internally stacked into a tensor with `2^log_num_polynomials` columns,
    /// where `log_num_polynomials = mle.num_variables() - num_encoding_variables` and
    /// `num_encoding_variables` is fixed by the PCS the context was initialized with.
    ///
    /// # Arguments
    /// * `mle` — the flat (unstacked) multilinear extension to commit to. The PCS's
    ///   `num_encoding_variables` is subtracted from `mle.num_variables()` to recover
    ///   the number of stacked polynomials.
    /// * `rng` — cryptographically secure random number generator.
    pub fn commit_mle<RNG>(
        &mut self,
        mle: slop_multilinear::Mle<GC::F, slop_alloc::CpuBackend>,
        rng: &mut RNG,
    ) -> Result<MleCommit, PcsCommitError>
    where
        RNG: rand::CryptoRng + rand::Rng,
        rand::distributions::Standard: rand::distributions::Distribution<GC::F>,
    {
        let pcs_prover = self.pcs_prover.as_ref().ok_or(PcsCommitError::NoPcsProver)?;
        let log_num_polynomials = log_num_polynomials(mle.num_variables(), pcs_prover)?;
        let commit = self
            .inner
            .commit_mle(mle, log_num_polynomials, pcs_prover, rng)
            .map(|idx| MleCommit { inner: idx })?;
        Ok(commit)
    }

    /// Generates a zero-knowledge proof. Consumes self.
    pub fn prove<RNG: rand::CryptoRng + rand::Rng>(mut self, rng: &mut RNG) -> ZkProof<GC>
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
    {
        // The "new flow"'s `verify` drains `replay.sent` by move, but the old flow
        // records sends and never replays — so release the recorded handles here.
        // They each hold an `Rc` clone of the inner context; left dangling, they'd
        // force `inner.prove` to deep-clone the context instead of unwrapping it.
        // (No-op in the new flow: the queue is already empty.)
        self.replay.sent.clear();
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
        Self::new(ZkProverContext::initialize(length, rng), pcs_prover)
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
        Self::new(ZkProverContext::initialize_only_lin_constraints(length, rng), pcs_prover)
    }
}

// ============================================================================
// No-PCS convenience methods
// ============================================================================

impl<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> ZkProverCtx<GC, NoPcsConfig<MK>> {
    /// Generates a proof without PCS support. Panics if PCS eval claims were registered.
    pub fn prove_without_pcs<RNG: rand::CryptoRng + rand::Rng>(
        mut self,
        rng: &mut RNG,
    ) -> ZkProof<GC>
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
    {
        // See `prove`: release recorded handles so the inner context can be unwrapped.
        self.replay.sent.clear();
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
        Self::new(ZkProverContext::initialize(length, rng), None)
    }

    /// Initializes a no-PCS prover with only linear constraints.
    pub fn initialize_without_pcs_only_lin<RNG: rand::CryptoRng + rand::Rng>(
        length: usize,
        rng: &mut RNG,
    ) -> Self
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
    {
        Self::new(ZkProverContext::initialize_only_lin_constraints(length, rng), None)
    }
}
