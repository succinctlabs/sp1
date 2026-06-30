use std::collections::VecDeque;

use rand::distributions::{Distribution, Standard};
use rand::{CryptoRng, Rng};
use slop_algebra::Dorroh;
use slop_alloc::CpuBackend;
use slop_challenger::{FieldChallenger, IopCtx};
use slop_commit::{Message, Rounds};
use slop_merkle_tree::TensorCsProver;
use slop_multilinear::{Mle, OracleEval, Point};
use thiserror::Error;

use crate::compiler::{ConstraintCtx, MleEvalClaim, ReadingCtx, SendingCtx, TranscriptReadError};
use crate::zk::inner::{
    ConstraintContextInner, ConstraintContextInnerExt, MleCommitmentIndex, ProverValue,
    ZkPcsProver, ZkProveError, ZkProverContext,
};
use crate::zk::verifier_ctx::{default_stacked_eval_claims, MleCommit};
use crate::zk::{ZkIopCtx, ZkProof};

/// The full `ZkProveError` instantiation for a [`ZkProverCtx<GC, PC>`]. Spells
/// out the two error parameters (PCS-prover error, merkleizer error) using `PC`.
#[allow(type_alias_bounds)]
pub type ZkProverCtxProveError<GC: ZkIopCtx, PC: PcsProverConfig<GC>> = ZkProveError<
    <PC::PcsProver as ZkPcsProver<GC, PC::Merkelizer>>::ProveError,
    <PC::Merkelizer as TensorCsProver<GC, CpuBackend>>::ProverError,
>;

/// Error returned by the `ZkProverCtx::initialize*` constructors — the merkleizer
/// can fail when committing to the initial mask vector.
#[allow(type_alias_bounds)]
pub type ZkProverCtxInitError<GC: ZkIopCtx, PC: PcsProverConfig<GC>> =
    <PC::Merkelizer as TensorCsProver<GC, CpuBackend>>::ProverError;

/// Auto-implemented trait that bundles the merkle commitment bounds needed by prover code.
///
/// Any type implementing `TensorCsProver + ComputeTcsOpenings + Default` automatically
/// satisfies this trait. Pass it as a separate generic `MK: ZkMerkleizer<GC>` on
/// prover-side structs and functions instead of baking it into `ZkIopCtx`.
pub trait ZkMerkleizer<GC: IopCtx>:
    TensorCsProver<GC, CpuBackend> + slop_merkle_tree::ComputeTcsOpenings<GC, CpuBackend> + Default
{
}

impl<MK, GC: IopCtx> ZkMerkleizer<GC> for MK where
    MK: TensorCsProver<GC, CpuBackend>
        + slop_merkle_tree::ComputeTcsOpenings<GC, CpuBackend>
        + Default
{
}

/// Type alias for the prover data produced by a `ZkMerkleizer`.
pub type MerkleProverData<GC, MK> = <MK as TensorCsProver<GC, CpuBackend>>::ProverData;

/// Trait packaging PCS choices for the prover.
pub trait PcsProverConfig<GC: ZkIopCtx> {
    type Merkelizer: ZkMerkleizer<GC>;
    type PcsProver: ZkPcsProver<GC, Self::Merkelizer>;
}

/// The PCS opening-proof wire format produced by a [`PcsProverConfig`]'s PCS prover.
#[allow(type_alias_bounds)]
pub type PcsProofOf<GC: ZkIopCtx, PC: PcsProverConfig<GC>> =
    <PC::PcsProver as ZkPcsProver<GC, PC::Merkelizer>>::Proof;

/// The PCS prover data produced by a [`PcsProverConfig`]'s PCS prover.
#[allow(type_alias_bounds)]
pub type PcsProverDataOf<GC: ZkIopCtx, PC: PcsProverConfig<GC>> =
    <PC::PcsProver as ZkPcsProver<GC, PC::Merkelizer>>::ProverData;

/// An abstract representation of a prover transcript extension field element.
///
/// Either a concrete field constant (`Dorroh::Constant`) or an opaque expression index
/// into the prover transcript (`Dorroh::Element`).
#[allow(type_alias_bounds)]
pub type ProverTranscriptElement<GC: ZkIopCtx, PC: PcsProverConfig<GC>> =
    Dorroh<GC::EF, ProverValue<GC, PC::Merkelizer, PcsProverDataOf<GC, PC>, PcsProofOf<GC, PC>>>;

pub struct ZkProverCtx<GC: ZkIopCtx, PC: PcsProverConfig<GC>> {
    inner: ZkProverContext<GC, PC::Merkelizer, PcsProverDataOf<GC, PC>, PcsProofOf<GC, PC>>,
    pcs_prover: Option<PC::PcsProver>,
    /// Replay log backing the prover's [`ReadingCtx`] impl.
    ///
    /// During the `SendingCtx` (compute) pass we record, in order, every
    /// transcript handle returned by `send_*`, every sampled challenge, and
    /// every committed oracle. The `ReadingCtx` impl then replays them — purely
    /// from these buffers, *without* touching the challenger — so the prover can
    /// run the exact same unified `verify` body the verifier runs. Leaving the
    /// challenger untouched is what keeps the post-compute Fiat-Shamir state
    /// (used by `prove()` to derive PCS openings) intact.
    replay: ProverReplay<GC, PC>,
    /// Set once any MLE-eval claim (eager PCS opening) has been discharged. Guards against
    /// further transcript reads, which would read past the (terminal) PCS openings.
    pcs_claim_made: bool,
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
        inner: ZkProverContext<GC, PC::Merkelizer, PcsProverDataOf<GC, PC>, PcsProofOf<GC, PC>>,
        pcs_prover: Option<PC::PcsProver>,
    ) -> Self {
        Self { inner, pcs_prover, replay: ProverReplay::default(), pcs_claim_made: false }
    }
}

// ============================================================================
// Conversion helper: ProverTranscriptElement → ProverValue
// ============================================================================

fn into_prover_value<GC: ZkIopCtx, PC: PcsProverConfig<GC>>(
    elem: ProverTranscriptElement<GC, PC>,
    ctx: &mut ZkProverContext<GC, PC::Merkelizer, PcsProverDataOf<GC, PC>, PcsProofOf<GC, PC>>,
) -> ProverValue<GC, PC::Merkelizer, PcsProverDataOf<GC, PC>, PcsProofOf<GC, PC>> {
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
    type MleCommit = MleCommit;
    // MLE-eval openings are discharged eagerly, so an assertion can fail here (missing PCS prover,
    // duplicate opening, or a PCS-prover error). The plain `assert_zero`/`assert_a_times_b_equals_c`
    // only queue constraints and never fail, so they return `Ok(())`.
    type AssertError = ZkProverCtxProveError<GC, PC>;

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
        point: &Point<GC::EF>,
    ) -> Result<(), Self::AssertError> {
        // No custom decomposition supplied: build the default single-commitment stacked claims
        // (eq-coefficient combiner + matching reduced point) and defer to the general method. The
        // first commitment's column count is shared by the whole batch.
        let log_num_cols = self.inner.commitment_log_num_cols(claims[0].0.inner);
        let (reduced_point, eval_claims) = default_stacked_eval_claims(point, log_num_cols, claims);
        self.assert_mle_multi_eval_with_oracle(eval_claims, &reduced_point)
    }

    /// The general PCS assertion: every commitment read by any claim is opened together at `point`
    /// in a single base proof; each claim's combiner then runs over its own commitments' columns to
    /// assert `claimed_eval == oracle_eval(columns)`.
    fn assert_mle_multi_eval_with_oracle<O: OracleEval<Self::Expr, Self::Expr>>(
        &mut self,
        claims: Vec<MleEvalClaim<MleCommit, ProverTranscriptElement<GC, PC>, O>>,
        point: &Point<GC::EF>,
    ) -> Result<(), Self::AssertError> {
        self.pcs_claim_made = true;

        // Open all the claims' commitments (flattened in claim order) together at `point` in one
        // base proof.
        let commitment_indices: Rounds<MleCommitmentIndex> =
            claims.iter().flat_map(|c| c.commits.iter().map(|commit| commit.inner)).collect();
        let per_commit_cols = match self.pcs_prover.as_ref() {
            Some(pcs_prover) => self.inner.open_mle_eval(pcs_prover, commitment_indices, point)?,
            None => return Err(ZkProveError::NoPcsProver),
        };

        // Hand each claim back its commitments' columns (a `Rounds` in `commits` order, the idiom
        // the combiner consumes) and constrain the combined value to the claimed eval.
        let mut cols_iter = per_commit_cols.into_iter();
        for claim in claims {
            let claim_cols: Vec<Vec<ProverTranscriptElement<GC, PC>>> = claim
                .commits
                .iter()
                .map(|_| {
                    cols_iter
                        .next()
                        .expect("one column set per opened commitment")
                        .into_iter()
                        .map(Dorroh::Element)
                        .collect()
                })
                .collect();
            let rounds: Rounds<&[ProverTranscriptElement<GC, PC>]> =
                claim_cols.iter().map(|c| c.as_slice()).collect();
            let combined = claim.oracle_eval.evaluate_oracle(rounds, 0);
            self.assert_zero(claim.claimed_eval - combined)?;
        }
        Ok(())
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
        let challenge = self.inner.with_challenger(|c| c.sample_ext_element());
        self.replay.challenges.push(challenge);
        challenge
    }

    fn num_encoding_variables(&self) -> u32 {
        self.pcs_prover
            .as_ref()
            .expect("num_encoding_variables requires a PCS-backed context")
            .num_encoding_variables()
    }

    fn commit_mle<RNG: CryptoRng + Rng>(
        &mut self,
        mle: Message<Mle<GC::F>>,
        rng: &mut RNG,
    ) -> Result<MleCommit, PcsCommitError>
    where
        Standard: Distribution<GC::F>,
    {
        let pcs_prover = self.pcs_prover.as_ref().ok_or(PcsCommitError::NoPcsProver)?;
        // The input is pre-stacked: each `mle[i]` is a `[2^num_encoding_variables, cols_i]`
        // block-column data component, so every component's columns are over exactly
        // `num_encoding_variables` variables.
        let num_encoding_variables = pcs_prover.num_encoding_variables();
        for component in mle.iter() {
            let num_variables = component.num_variables();
            if num_variables != num_encoding_variables {
                return Err(PcsCommitError::WrongEncodingWidth {
                    num_variables,
                    num_encoding_variables,
                });
            }
        }
        let commit =
            self.inner.commit_mle(mle, pcs_prover, rng).map(|idx| MleCommit { inner: idx })?;
        self.replay.oracles.push(commit);
        Ok(commit)
    }
}

// ============================================================================
// ReadingCtx impl
// ============================================================================
//
// Pure record/replay over the buffers populated during the `SendingCtx` pass.
// Crucially, none of these methods touch the challenger: challenges are replayed
// from `replay.challenges` rather than re-sampled, so the prover's Fiat-Shamir
// state (already advanced to its final value by the compute pass) is left exactly
// where `prove()` needs it for PCS-opening derivation.

impl<GC: ZkIopCtx, PC: PcsProverConfig<GC>> ReadingCtx for ZkProverCtx<GC, PC> {
    fn read_exact(&mut self, buf: &mut [Self::Expr]) -> Result<(), TranscriptReadError> {
        if self.pcs_claim_made {
            return Err(TranscriptReadError::ReadAfterPcsClaim);
        }
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
    /// A committed data component's variable count does not match the PCS's fixed encoding width
    /// (pre-stacked components must each be over exactly `num_encoding_variables` variables).
    #[error(
        "MLE component has {num_variables} variables, but the PCS's fixed encoding width is \
         {num_encoding_variables}"
    )]
    WrongEncodingWidth { num_variables: u32, num_encoding_variables: u32 },
}

impl<GC: ZkIopCtx, PC: PcsProverConfig<GC>> ZkProverCtx<GC, PC> {
    /// Generates a zero-knowledge proof. Consumes self.
    pub fn prove<RNG: CryptoRng + Rng>(
        mut self,
        rng: &mut RNG,
    ) -> Result<ZkProof<GC, PcsProofOf<GC, PC>>, ZkProverCtxProveError<GC, PC>>
    where
        Standard: Distribution<GC::EF>,
    {
        // Release any transcript handles still sitting in the replay queue. Each holds an
        // `Rc` clone of the inner context; left dangling, they'd force `inner.prove` to
        // deep-clone the context instead of unwrapping it. The unified `verify` body drains
        // this queue by move, so it is normally already empty here — this is a safety net for
        // callers that `prove()` without first replaying `verify`.
        self.replay.sent.clear();
        // Widen the no-PCS inner error (`ZkProveError<Infallible, _>`) into this context's full
        // error type via the panic-free `widen` conversion.
        self.inner.prove(rng).map_err(ZkProveError::widen)
    }

    pub fn initialize<RNG: CryptoRng + Rng>(
        length: usize,
        rng: &mut RNG,
        pcs_prover: Option<PC::PcsProver>,
    ) -> Result<Self, ZkProverCtxInitError<GC, PC>>
    where
        Standard: Distribution<GC::EF>,
    {
        Ok(Self::new(ZkProverContext::initialize(length, rng)?, pcs_prover))
    }

    /// Initializes a prover that supports only linear constraints.
    pub fn initialize_only_lin_constraints<RNG: CryptoRng + Rng>(
        length: usize,
        rng: &mut RNG,
        pcs_prover: Option<PC::PcsProver>,
    ) -> Result<Self, ZkProverCtxInitError<GC, PC>>
    where
        Standard: Distribution<GC::EF>,
    {
        Ok(Self::new(ZkProverContext::initialize_only_lin_constraints(length, rng)?, pcs_prover))
    }
}
