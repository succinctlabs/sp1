use slop_algebra::TwoAdicField;
use slop_alloc::CpuBackend;
use slop_basefold::{BasefoldVerifier, FriConfig};
use slop_basefold_prover::{BasefoldProver, BasefoldProverError};
use slop_challenger::{CanObserve, FieldChallenger, IopCtx};
use slop_commit::{Message, Rounds};
use slop_merkle_tree::ComputeTcsOpenings;
use slop_multilinear::{Mle, MultilinearPcsProver, Point};
use slop_stacked::{
    StackedBasefoldProof, StackedBasefoldProverData, StackedPcsProver, StackedPcsVerifier,
};

use thiserror::Error;

use crate::compiler::{ConstraintCtx, ReadingCtx, SendingCtx, TranscriptReadError};

/// Error returned by [`TransparentProverCtx::commit_mle`].
///
/// Wraps the underlying basefold prover error and adds the shape-check failures that the
/// transparent context performs before handing the MLE to the PCS.
#[derive(Debug, Error)]
pub enum TransparentCommitError<E: std::error::Error + 'static> {
    /// `commit_mle` was called on a context built via [`TransparentProverCtx::initialize_without_pcs`].
    #[error("commit_mle called on a transparent prover built without a PCS")]
    NoPcsProver,
    /// The MLE has fewer variables than the PCS's fixed encoding width.
    #[error(
        "MLE has {num_variables} variables, fewer than the PCS's \
         {num_encoding_variables} encoding variables"
    )]
    MleTooSmall { num_variables: u32, num_encoding_variables: u32 },
    /// The MLE's implied number of stacked polynomials does not match the PCS's
    /// configured batch size.
    #[error("MLE implies batch size {got}, but the PCS was configured with batch size {expected}")]
    BatchSizeMismatch { expected: usize, got: usize },
    /// The underlying basefold prover failed.
    #[error(transparent)]
    Basefold(#[from] BasefoldProverError<E>),
}

/// Error returned by [`TransparentProverCtx::prove`].
///
/// Wraps the underlying basefold prover error and adds the missing-PCS variant
/// for contexts built via [`TransparentProverCtx::initialize_without_pcs`] that
/// nonetheless emitted MLE-eval claims.
#[derive(Debug, Error)]
pub enum TransparentProveError<E: std::error::Error + 'static> {
    /// MLE-eval claims were registered but the context was built via
    /// [`TransparentProverCtx::initialize_without_pcs`].
    #[error("MLE-eval claims exist but the transparent prover has no PCS backend")]
    NoPcsProver,
    /// The underlying basefold prover failed during opening proof generation.
    #[error(transparent)]
    Basefold(#[from] BasefoldProverError<E>),
}

/// Convenience alias for the stacked-basefold PCS prover data attached to each
/// committed oracle.
#[allow(type_alias_bounds)]
pub type TransparentProverData<GC: IopCtx, MK: ComputeTcsOpenings<GC, CpuBackend>> =
    StackedBasefoldProverData<Mle<GC::F>, GC::F, MK::ProverData>;

/// Oracle handle on the transparent prover side.
///
/// Just an index into [`TransparentProverCtx::oracles`] (which owns the commitment,
/// shape, and heavy stacked-basefold prover data) — mirroring the verifier's
/// [`TransparentVerifierOracle`](super::TransparentVerifierOracle) and the ZK
/// backend's `MleCommit`. Being `Copy`, handing it around (including replaying it)
/// is free; the `prover_data` is never copied just to move a handle, only when an
/// opening proof genuinely needs an owned copy at `prove()`.
#[derive(Clone, Copy, Debug)]
pub struct TransparentMleOracle {
    /// Index into `TransparentProverCtx::oracles`.
    idx: usize,
}

/// One committed oracle: its commitment + shape (emitted into the proof) and the
/// stacked-basefold prover data needed to answer openings. Indexed by
/// [`TransparentMleOracle::idx`]; the `prover_data` is `take()`n (or cloned, for
/// repeat opens) at `prove()` so the last opening can move it out without a copy.
struct OracleEntry<GC: IopCtx, MK: ComputeTcsOpenings<GC, CpuBackend>> {
    commitment: GC::Digest,
    num_encoding_variables: u32,
    log_num_polynomials: u32,
    prover_data: Option<TransparentProverData<GC, MK>>,
}

/// One group of pending MLE-evaluation claims — all at a single shared opening point,
/// as emitted by a single `assert_mle_multi_eval` call. Each group is later discharged
/// into a single stacked-basefold opening proof at `prove()` time. Oracles are stored
/// by index; their `prover_data` is fetched from `oracle_store` at `prove()` time.
struct PendingEvalClaims<EF> {
    oracle_indices: Vec<usize>,
    evals: Vec<EF>,
    point: Point<EF>,
}

/// Finalized transparent proof: raw transcript, oracle digests paired with their
/// shape `(num_encoding_variables, log_num_polynomials)`, and one stacked-basefold
/// opening proof per `assert_mle_multi_eval` call.
pub struct TransparentProof<GC: IopCtx> {
    pub transcript: Vec<Vec<GC::EF>>,
    pub oracle_commits: Vec<(GC::Digest, u32, u32)>,
    pub pcs_proofs: Vec<StackedBasefoldProof<GC>>,
}

/// Transparent prover context.
///
/// Runs a veil protocol without zero-knowledge compilation: the "proof" is a plain
/// transcript of sent values and oracle commitments, and Fiat-Shamir challenges are
/// drawn from a challenger observing that transcript.
///
/// Unlike a more elaborate compiled prover, this context does not track polynomial
/// constraints (those are the verifier's concern in the raw protocol). It *does*,
/// however, record every `assert_mle_eval` / `assert_mle_multi_eval` claim so that
/// at `prove()` time it can batch them all into a single stacked-basefold opening.
///
/// Commitments go through [`StackedPcsProver`] from `slop-stacked`. The transparent
/// context treats every `commit_mle` as its own round: we flatten the stacked PCS's
/// `Rounds<_>` abstraction by keeping one handle per commit and bundling them into
/// `Rounds` only at `prove()` time.
///
/// Each `assert_mle_multi_eval` call is recorded as its own claim group (one opening
/// point, one or more oracles at that point) and becomes one stacked-basefold opening
/// proof. Multiple calls at different points turn into multiple proofs — matching the
/// zk case, which emits one `PcsProof` per claim group.
pub struct TransparentProverCtx<GC, MK>
where
    GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
    MK: ComputeTcsOpenings<GC, CpuBackend>,
{
    /// All sent extension-field messages, grouped by `send_value` / `send_values` call.
    transcript: Vec<Vec<GC::EF>>,
    /// Fiat-Shamir challenger; observes every sent message and oracle commitment.
    challenger: GC::Challenger,
    /// Configured stacked-basefold prover used to commit MLEs and produce openings;
    /// `None` for protocols that don't use MLE commitments (e.g. pure-constraint
    /// proofs like `root.rs`).
    pcs_prover: Option<StackedPcsProver<MK, GC>>,
    /// All committed oracles in send order: commitment + shape + prover data. The
    /// commitments/shapes are emitted into the proof; the prover data is consumed at
    /// `prove()`. `TransparentMleOracle` is just an index into this vector.
    oracles: Vec<OracleEntry<GC, MK>>,
    /// Accumulated MLE-eval claim groups to be discharged at `prove()` time; one
    /// entry per `assert_mle_multi_eval` call.
    pending_eval_claims: Vec<PendingEvalClaims<GC::EF>>,
    /// Replay log backing the prover's [`ReadingCtx`] impl (the "new flow").
    /// Records, in order, every value sent and challenge sampled during the
    /// `SendingCtx` pass, so the unified `verify` body can be replayed on the prover
    /// without re-deriving (or advancing) Fiat-Shamir. Oracles need no buffer: their
    /// indices are assigned `0, 1, 2, …` in commit order, so a cursor into `oracles`
    /// reproduces them.
    replay_sent: Vec<GC::EF>,
    replay_sent_cursor: usize,
    replay_challenges: Vec<GC::EF>,
    replay_challenge_cursor: usize,
    replay_oracle_cursor: usize,
}

impl<GC, MK> TransparentProverCtx<GC, MK>
where
    GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
    MK: ComputeTcsOpenings<GC, CpuBackend>,
{
    pub fn initialize(pcs_prover: StackedPcsProver<MK, GC>) -> Self {
        Self::new_inner(Some(pcs_prover))
    }

    /// Construct a transparent prover with no PCS backend. `commit_mle` will then
    /// panic, and `prove` succeeds trivially (no MLE openings to produce).
    pub fn initialize_without_pcs() -> Self {
        Self::new_inner(None)
    }

    fn new_inner(pcs_prover: Option<StackedPcsProver<MK, GC>>) -> Self {
        Self {
            transcript: Vec::new(),
            challenger: GC::default_challenger(),
            pcs_prover,
            oracles: Vec::new(),
            pending_eval_claims: Vec::new(),
            replay_sent: Vec::new(),
            replay_sent_cursor: 0,
            replay_challenges: Vec::new(),
            replay_challenge_cursor: 0,
            replay_oracle_cursor: 0,
        }
    }

    /// Finalize the proof: consume the context and emit the raw transcript, oracle
    /// commits, and one stacked-basefold opening proof per `assert_mle_multi_eval`
    /// call group. `rng` is unused — transparent mode doesn't mask.
    pub fn prove<RNG: rand::CryptoRng + rand::Rng>(
        mut self,
        _rng: &mut RNG,
    ) -> Result<TransparentProof<GC>, TransparentProveError<MK::ProverError>>
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
        // Only needed for the multi-open path below (an oracle opened at >1 point);
        // single-open proofs move the data out of `oracles` and never clone.
        TransparentProverData<GC, MK>: Clone,
    {
        let pcs_proofs = if self.pending_eval_claims.is_empty() {
            Vec::new()
        } else {
            // Per-index opening multiplicity: an oracle opened N times needs N owned
            // copies of its prover data. We move the data out on its *last* opening and
            // clone only for the earlier ones, so single-open proofs do zero clones.
            let mut remaining = vec![0usize; self.oracles.len()];
            for group in &self.pending_eval_claims {
                for &idx in &group.oracle_indices {
                    remaining[idx] += 1;
                }
            }

            let pcs_prover = self.pcs_prover.as_ref().ok_or(TransparentProveError::NoPcsProver)?;
            // `prove_trusted_evaluation` ignores its `evaluation_claim` argument — the
            // per-oracle claims are checked by the verifier against the proof's embedded
            // batch evaluations — but we still need to pass something.
            let placeholder_eval = <GC::EF as slop_algebra::AbstractField>::zero();

            let mut pcs_proofs = Vec::with_capacity(self.pending_eval_claims.len());
            for group in std::mem::take(&mut self.pending_eval_claims) {
                let prover_datas: Vec<_> = group
                    .oracle_indices
                    .iter()
                    .map(|&idx| {
                        remaining[idx] -= 1;
                        let data = &mut self.oracles[idx].prover_data;
                        if remaining[idx] == 0 {
                            data.take().expect("oracle data already taken")
                        } else {
                            data.as_ref().expect("oracle data missing").clone()
                        }
                    })
                    .collect();
                let rounds = Rounds { rounds: prover_datas };
                pcs_proofs.push(pcs_prover.prove_trusted_evaluation(
                    group.point,
                    placeholder_eval,
                    rounds,
                    &mut self.challenger,
                )?);
            }
            pcs_proofs
        };

        let oracle_commits = self
            .oracles
            .iter()
            .map(|o| (o.commitment, o.num_encoding_variables, o.log_num_polynomials))
            .collect();

        Ok(TransparentProof { transcript: self.transcript, oracle_commits, pcs_proofs })
    }
}

/// Construct a matched stacked-basefold prover / verifier pair with a default FRI
/// configuration. Mirror of
/// [`initialize_zk_prover_and_verifier`](crate::zk::stacked_pcs::initialize_zk_prover_and_verifier),
/// but with no zero-knowledge wrapper.
///
/// # Arguments
/// * `num_expected_commitments` — upper bound on the number of MLE commitments made
///   during the protocol (passed through to the underlying `BasefoldVerifier`).
/// * `num_encoding_variables` — number of variables per stacked polynomial (encoding
///   width). Every subsequent [`commit_mle`](crate::compiler::SendingCtx::commit_mle)
///   / [`read_oracle`](crate::compiler::ReadingCtx::read_oracle) call must use a
///   matching `num_encoding_variables`.
/// * `log_num_polynomials` — log2 of the number of stacked polynomials per commit.
///   Fixes the prover's `batch_size` at `1 << log_num_polynomials`; all commits must
///   use this value.
pub fn initialize_transparent_prover_and_verifier<GC, MK>(
    num_expected_commitments: usize,
    num_encoding_variables: u32,
    log_num_polynomials: u32,
) -> (StackedPcsProver<MK, GC>, StackedPcsVerifier<GC>)
where
    GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
    MK: ComputeTcsOpenings<GC, CpuBackend> + Default,
{
    let basefold_verifier =
        BasefoldVerifier::<GC>::new(FriConfig::default_fri_config(), num_expected_commitments);
    let basefold_prover = BasefoldProver::<GC, MK>::new(&basefold_verifier);
    let stacked_prover = StackedPcsProver::new(
        basefold_prover,
        num_encoding_variables,
        1usize << log_num_polynomials,
    );
    let stacked_verifier = StackedPcsVerifier::new(basefold_verifier, num_encoding_variables);
    (stacked_prover, stacked_verifier)
}

// ============================================================================
// ConstraintCtx: polynomial-identity asserts are no-ops; MLE-eval asserts queue
//                claims for discharge at `prove()` time.
// ============================================================================

impl<GC, MK> ConstraintCtx for TransparentProverCtx<GC, MK>
where
    GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
    MK: ComputeTcsOpenings<GC, CpuBackend>,
{
    type Field = GC::F;
    type Extension = GC::EF;
    type Expr = GC::EF;
    type Challenge = GC::EF;
    type MleOracle = TransparentMleOracle;
    type AssertError = std::convert::Infallible;

    fn assert_zero(&mut self, _expr: Self::Expr) -> Result<(), Self::AssertError> {
        Ok(())
    }

    fn assert_mle_multi_eval(
        &mut self,
        claims: Vec<(Self::MleOracle, Self::Expr)>,
        point: Point<Self::Challenge>,
    ) {
        let mut oracle_indices = Vec::with_capacity(claims.len());
        let mut evals = Vec::with_capacity(claims.len());
        for (oracle, eval) in claims {
            oracle_indices.push(oracle.idx);
            evals.push(eval);
        }
        self.pending_eval_claims.push(PendingEvalClaims { oracle_indices, evals, point });
    }
}

// ============================================================================
// SendingCtx: push values onto the transcript, observe them, commit MLEs, and
// finalize the proof.
// ============================================================================

impl<GC, MK> SendingCtx for TransparentProverCtx<GC, MK>
where
    GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
    MK: ComputeTcsOpenings<GC, CpuBackend>,
{
    type CommitError = TransparentCommitError<MK::ProverError>;

    fn send_value(&mut self, value: GC::EF) -> GC::EF {
        self.challenger.observe_ext_element(value);
        self.transcript.push(vec![value]);
        self.replay_sent.push(value);
        value
    }

    fn send_values(&mut self, values: &[GC::EF]) -> Vec<GC::EF> {
        for &v in values {
            self.challenger.observe_ext_element(v);
        }
        self.transcript.push(values.to_vec());
        self.replay_sent.extend_from_slice(values);
        values.to_vec()
    }

    fn to_value(&self, expr: &GC::EF) -> GC::EF {
        *expr
    }

    fn sample(&mut self) -> GC::EF {
        let challenge = self.challenger.sample_ext_element();
        self.replay_challenges.push(challenge);
        challenge
    }

    /// The number of stacked polynomials (`mle.num_variables() - num_encoding_variables`)
    /// must match the stacked-PCS's configured `batch_size` (= 2^log_num_polynomials).
    /// `rng` is unused — transparent mode doesn't mask.
    fn commit_mle<RNG: rand::CryptoRng + rand::Rng>(
        &mut self,
        mle: Mle<GC::F>,
        _rng: &mut RNG,
    ) -> Result<Self::MleOracle, Self::CommitError>
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::F>,
    {
        let pcs_prover = self.pcs_prover.as_ref().ok_or(TransparentCommitError::NoPcsProver)?;
        let num_encoding_variables = pcs_prover.log_stacking_height;
        let num_variables = mle.num_variables();
        let log_num_polynomials = num_variables
            .checked_sub(num_encoding_variables)
            .ok_or(TransparentCommitError::MleTooSmall { num_variables, num_encoding_variables })?;
        let expected_batch_size = 1usize << log_num_polynomials;
        if expected_batch_size != pcs_prover.batch_size {
            return Err(TransparentCommitError::BatchSizeMismatch {
                expected: pcs_prover.batch_size,
                got: expected_batch_size,
            });
        }
        let message = Message::from(vec![mle]);
        let (commitment, prover_data, _num_added_vals) = pcs_prover.commit_multilinears(message)?;
        self.challenger.observe(commitment);
        let idx = self.oracles.len();
        self.oracles.push(OracleEntry {
            commitment,
            num_encoding_variables,
            log_num_polynomials,
            prover_data: Some(prover_data),
        });
        // No replay buffer needed: `read_oracle` reconstructs this handle from a
        // cursor, since indices are assigned in commit order.
        Ok(TransparentMleOracle { idx })
    }
}

// ============================================================================
// ReadingCtx impl (prototype, "new flow")
// ============================================================================
//
// Pure record/replay over the buffers populated during the `SendingCtx` pass.
// Like the ZK prover, these methods never touch the challenger — challenges are
// replayed from `replay_challenges` — so the post-compute Fiat-Shamir state that
// `prove()` uses to derive PCS openings is left untouched.

impl<GC, MK> ReadingCtx for TransparentProverCtx<GC, MK>
where
    GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
    MK: ComputeTcsOpenings<GC, CpuBackend>,
{
    fn read_exact(&mut self, buf: &mut [Self::Expr]) -> Result<(), TranscriptReadError> {
        let end = self.replay_sent_cursor + buf.len();
        let slice = self
            .replay_sent
            .get(self.replay_sent_cursor..end)
            .ok_or(TranscriptReadError::TranscriptExhausted)?;
        buf.copy_from_slice(slice);
        self.replay_sent_cursor = end;
        Ok(())
    }

    fn read_oracle(&mut self, _num_variables: u32) -> Option<Self::MleOracle> {
        // Oracle indices are `0, 1, 2, …` in commit order, so the cursor *is* the
        // next handle — no recorded buffer required.
        let idx = self.replay_oracle_cursor;
        if idx >= self.oracles.len() {
            return None;
        }
        self.replay_oracle_cursor += 1;
        Some(TransparentMleOracle { idx })
    }

    fn sample(&mut self) -> Self::Challenge {
        let challenge = self.replay_challenges[self.replay_challenge_cursor];
        self.replay_challenge_cursor += 1;
        challenge
    }
}
