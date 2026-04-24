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

use crate::compiler::{ConstraintCtx, SendingCtx};

/// Convenience alias for the stacked-basefold PCS prover data attached to each
/// committed oracle.
#[allow(type_alias_bounds)]
pub type TransparentProverData<GC: IopCtx, MK: ComputeTcsOpenings<GC, CpuBackend>> =
    StackedBasefoldProverData<Mle<GC::F>, GC::F, MK::ProverData>;

/// Oracle handle on the transparent prover side.
///
/// Holds both the commitment (observable on the transcript) and the stacked-basefold
/// prover data, which the prover needs on hand to later answer openings.
/// `Clone` is supported so protocols that open the same commit at multiple points
/// can pass the oracle to `assert_mle_eval` more than once; it's a deep copy of
/// the stacked PCS prover data (not cheap — one copy per reuse).
#[derive(Clone)]
pub struct TransparentMleOracle<GC: IopCtx, MK: ComputeTcsOpenings<GC, CpuBackend>> {
    pub commitment: GC::Digest,
    pub prover_data: TransparentProverData<GC, MK>,
}

/// One group of pending MLE-evaluation claims — all at a single shared opening point,
/// as emitted by a single `assert_mle_multi_eval` call. Each group is later discharged
/// into a single stacked-basefold opening proof at `prove()` time.
struct PendingEvalClaims<GC: IopCtx, MK: ComputeTcsOpenings<GC, CpuBackend>> {
    prover_datas: Vec<TransparentProverData<GC, MK>>,
    evals: Vec<GC::EF>,
    point: Point<GC::EF>,
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
    /// All oracle commitments in send order, paired with their shape
    /// `(num_encoding_variables, log_num_polynomials)`.
    oracle_commits: Vec<(GC::Digest, u32, u32)>,
    /// Fiat-Shamir challenger; observes every sent message and oracle commitment.
    challenger: GC::Challenger,
    /// Configured stacked-basefold prover used to commit MLEs and produce openings;
    /// `None` for protocols that don't use MLE commitments (e.g. pure-constraint
    /// proofs like `root.rs`).
    pcs_prover: Option<StackedPcsProver<MK, GC>>,
    /// Accumulated MLE-eval claim groups to be discharged at `prove()` time; one
    /// entry per `assert_mle_multi_eval` call.
    pending_eval_claims: Vec<PendingEvalClaims<GC, MK>>,
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
            oracle_commits: Vec::new(),
            challenger: GC::default_challenger(),
            pcs_prover,
            pending_eval_claims: Vec::new(),
        }
    }

    /// Finalize the proof: consume the context and emit the raw transcript, oracle
    /// commits, and one stacked-basefold opening proof per `assert_mle_multi_eval`
    /// call group. `rng` is unused — transparent mode doesn't mask.
    pub fn prove<RNG: rand::CryptoRng + rand::Rng>(
        mut self,
        _rng: &mut RNG,
    ) -> Result<TransparentProof<GC>, BasefoldProverError<MK::ProverError>>
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
    {
        let pcs_proofs = if self.pending_eval_claims.is_empty() {
            Vec::new()
        } else {
            let pcs_prover = self
                .pcs_prover
                .as_ref()
                .expect("MLE-eval claims exist but transparent prover has no PCS backend");
            // `prove_trusted_evaluation` ignores its `evaluation_claim` argument — the
            // per-oracle claims are checked by the verifier against the proof's embedded
            // batch evaluations — but we still need to pass something.
            let placeholder_eval = <GC::EF as slop_algebra::AbstractField>::zero();
            self.pending_eval_claims
                .into_iter()
                .map(|group| {
                    let rounds = Rounds { rounds: group.prover_datas };
                    pcs_prover.prove_trusted_evaluation(
                        group.point,
                        placeholder_eval,
                        rounds,
                        &mut self.challenger,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        Ok(TransparentProof {
            transcript: self.transcript,
            oracle_commits: self.oracle_commits,
            pcs_proofs,
        })
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
    type MleOracle = TransparentMleOracle<GC, MK>;
    type AssertError = std::convert::Infallible;

    fn assert_zero(&mut self, _expr: Self::Expr) -> Result<(), Self::AssertError> {
        Ok(())
    }

    fn assert_mle_multi_eval(
        &mut self,
        claims: Vec<(Self::MleOracle, Self::Expr)>,
        point: Point<Self::Challenge>,
    ) {
        let mut prover_datas = Vec::with_capacity(claims.len());
        let mut evals = Vec::with_capacity(claims.len());
        for (oracle, eval) in claims {
            prover_datas.push(oracle.prover_data);
            evals.push(eval);
        }
        self.pending_eval_claims.push(PendingEvalClaims { prover_datas, evals, point });
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
    type CommitError = BasefoldProverError<MK::ProverError>;

    fn send_value(&mut self, value: GC::EF) -> GC::EF {
        self.challenger.observe_ext_element(value);
        self.transcript.push(vec![value]);
        value
    }

    fn send_values(&mut self, values: &[GC::EF]) -> Vec<GC::EF> {
        for &v in values {
            self.challenger.observe_ext_element(v);
        }
        self.transcript.push(values.to_vec());
        values.to_vec()
    }

    fn to_value(&self, expr: &GC::EF) -> GC::EF {
        *expr
    }

    fn sample(&mut self) -> GC::EF {
        self.challenger.sample_ext_element()
    }

    /// `log_num_polynomials` must match the stacked-PCS's configured `batch_size`
    /// (= 2^log_num_polynomials). `rng` is unused — transparent mode doesn't mask.
    /// Panics if the context was built without a PCS via `new_without_pcs`.
    fn commit_mle<RNG: rand::CryptoRng + rand::Rng>(
        &mut self,
        mle: Mle<GC::F>,
        log_num_polynomials: u32,
        _rng: &mut RNG,
    ) -> Result<Self::MleOracle, Self::CommitError>
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::F>,
    {
        let pcs_prover = self
            .pcs_prover
            .as_ref()
            .expect("commit_mle called on a transparent prover built without a PCS");
        assert_eq!(
            1usize << log_num_polynomials,
            pcs_prover.batch_size,
            "log_num_polynomials must match the stacked PCS's batch_size",
        );
        let num_encoding_variables = pcs_prover.log_stacking_height;
        let message = Message::from(vec![mle]);
        let (commitment, prover_data, _num_added_vals) = pcs_prover.commit_multilinears(message)?;
        self.challenger.observe(commitment);
        self.oracle_commits.push((commitment, num_encoding_variables, log_num_polynomials));
        Ok(TransparentMleOracle { commitment, prover_data })
    }
}
