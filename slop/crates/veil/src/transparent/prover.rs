use slop_algebra::TwoAdicField;
use slop_alloc::CpuBackend;
use slop_basefold::{BasefoldVerifier, FriConfig};
use slop_basefold_prover::BasefoldProver;
use slop_challenger::{CanObserve, FieldChallenger, IopCtx};
use slop_commit::Message;
use slop_merkle_tree::ComputeTcsOpenings;
use slop_multilinear::{BatchPcsProver, Mle, OracleEval, Point};
use slop_stacked::{StackedPcsProver, StackedPcsVerifier};

use thiserror::Error;

use crate::compiler::{ConstraintCtx, MleEvalClaim, ReadingCtx, SendingCtx, TranscriptReadError};
use crate::transparent::pcs::{self, TransparentCommitData};

/// Error returned by [`TransparentProverCtx::commit_mle`]. `E` is the base PCS prover's error.
#[derive(Debug, Error)]
pub enum TransparentCommitError<E: std::error::Error + 'static> {
    /// `commit_mle` was called on a context built via [`TransparentProverCtx::initialize_without_pcs`].
    #[error("commit_mle called on a transparent prover built without a PCS")]
    NoPcsProver,
    /// A committed data component's variable count does not match the PCS's fixed encoding width
    /// (pre-stacked components must each be over exactly `num_encoding_variables` variables).
    #[error(
        "MLE component has {num_variables} variables, but the PCS's fixed encoding width is \
         {num_encoding_variables}"
    )]
    WrongEncodingWidth { num_variables: u32, num_encoding_variables: u32 },
    /// The underlying base PCS prover failed.
    #[error(transparent)]
    Pcs(E),
}

/// Error returned by [`TransparentProverCtx::prove`] / the eager `assert_mle_*` openings. `E` is the
/// base PCS prover's error.
#[derive(Debug, Error)]
pub enum TransparentProveError<E: std::error::Error + 'static> {
    /// MLE-eval claims were registered but the context was built via
    /// [`TransparentProverCtx::initialize_without_pcs`].
    #[error("MLE-eval claims exist but the transparent prover has no PCS backend")]
    NoPcsProver,
    /// The underlying base PCS prover failed during opening proof generation.
    #[error(transparent)]
    Pcs(E),
}

/// Basefold specialization of the transparent backend's base PCS prover: the Basefold prover
/// pinned to its fixed encoding width (= stacking height). The fixed width and the mid-proof RLC
/// encoder both come from the base [`BatchPcsProver`] itself; the transparent backend does its
/// own (mask-free) stacking through [`crate::transparent::pcs`].
#[allow(type_alias_bounds)]
pub type BasefoldTransparentProver<
    GC: IopCtx<F: TwoAdicField>,
    MK: ComputeTcsOpenings<GC, CpuBackend>,
> = StackedPcsProver<MK, GC>;

/// Oracle handle on the transparent prover side.
///
/// Just an index into [`TransparentProverCtx::oracles`] (which owns the commitment,
/// shape, and heavy stacked-basefold prover data) — mirroring the verifier's
/// [`TransparentVerifierOracle`](super::TransparentVerifierOracle) and the ZK
/// backend's `MleCommit`. Being `Copy`, handing it around (including replaying it)
/// is free.
#[derive(Clone, Copy, Debug)]
pub struct TransparentMleOracle {
    /// Index into `TransparentProverCtx::oracles`.
    idx: usize,
}

/// One committed oracle: its commitment + shape (emitted into the proof) and the
/// stacked-basefold prover data needed to answer openings. Indexed by
/// [`TransparentMleOracle::idx`]; the `prover_data` is cloned (cheaply —
/// `Arc`/`Message`-backed) by each eager opening, since an oracle may be opened at
/// several points.
struct OracleEntry<GC: IopCtx, Inner: BatchPcsProver<GC>> {
    commitment: GC::Digest,
    num_encoding_variables: u32,
    log_num_polynomials: u32,
    prover_data: Option<TransparentCommitData<GC, Inner>>,
}

/// Finalized transparent proof: raw transcript, oracle digests paired with their shape
/// `(num_encoding_variables, log_num_polynomials)`, and one base-PCS opening proof per
/// `assert_mle_multi_eval` call, in call order. `Proof` is the base PCS's proof type.
pub struct TransparentProof<GC: IopCtx, Proof> {
    pub transcript: Vec<Vec<GC::EF>>,
    pub oracle_commits: Vec<(GC::Digest, u32, u32)>,
    pub pcs_proofs: Vec<Proof>,
}

/// Basefold specialization of [`TransparentProof`].
pub type BasefoldTransparentProof<GC> = TransparentProof<GC, slop_basefold::BasefoldProof<GC>>;

/// Basefold specialization of [`TransparentProverCtx`] (the context used in tests/examples).
#[allow(type_alias_bounds)]
pub type BasefoldTransparentProverCtx<
    GC: IopCtx<F: TwoAdicField>,
    MK: ComputeTcsOpenings<GC, CpuBackend>,
> = TransparentProverCtx<GC, StackedPcsProver<MK, GC>>;

/// Transparent prover context.
///
/// Runs a veil protocol without zero-knowledge compilation: the "proof" is a plain
/// transcript of sent values and oracle commitments, and Fiat-Shamir challenges are
/// drawn from a challenger observing that transcript.
///
/// Unlike a more elaborate compiled prover, this context does not track polynomial
/// constraints (those are the verifier's concern in the raw protocol). MLE-eval
/// openings are discharged **eagerly**: each `assert_mle_eval` / `assert_mle_multi_eval`
/// call immediately produces its stacked-basefold opening proof (advancing the
/// Fiat-Shamir challenger over it) and pushes it onto `pcs_proofs`, matching the ZK
/// backend. `prove()` then just emits the already-collected proofs.
///
/// Commitments and openings go through the base [`BatchPcsProver`] directly (via
/// [`crate::transparent::pcs`]), with the transparent backend doing its own mask-free stacking —
/// no stacked-protocol machinery, and no dependence on the ZK stacked PCS. Each
/// `assert_mle_multi_eval` call (one opening point, one or more oracles at that point) becomes one
/// opening proof — matching the zk case, which emits one `PcsProof` per claim group.
pub struct TransparentProverCtx<GC, Inner>
where
    GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
    Inner: BatchPcsProver<GC>,
{
    /// All sent extension-field messages, grouped by `send_value` / `send_values` call.
    transcript: Vec<Vec<GC::EF>>,
    /// Fiat-Shamir challenger; observes every sent message and oracle commitment.
    challenger: GC::Challenger,
    /// Configured base PCS prover used to commit MLEs and produce openings; `None` for
    /// protocols that don't use MLE commitments (e.g. pure-constraint proofs like `root.rs`).
    pcs_prover: Option<Inner>,
    /// All committed oracles in send order: commitment + shape + prover data. The
    /// commitments/shapes are emitted into the proof; the prover data is read (cloned)
    /// by each eager opening. `TransparentMleOracle` is just an index into this vector.
    oracles: Vec<OracleEntry<GC, Inner>>,
    /// Opening proofs produced eagerly at each `assert_mle_multi_eval` call, in call order.
    /// Moved into the [`TransparentProof`] by `prove()`.
    pcs_proofs: Vec<Inner::Proof>,
    /// Replay log backing the prover's [`ReadingCtx`] impl.
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
    /// Set once any MLE-eval claim has been recorded. Guards against further transcript reads,
    /// which would read past the (terminal) PCS openings.
    pcs_claim_made: bool,
}

impl<GC, PCS> TransparentProverCtx<GC, PCS>
where
    GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
    PCS: BatchPcsProver<GC>,
{
    pub fn initialize(pcs_prover: PCS) -> Self {
        Self::new_inner(Some(pcs_prover))
    }

    /// Construct a transparent prover with no PCS backend. `commit_mle` will then
    /// panic, and `prove` succeeds trivially (no MLE openings to produce).
    pub fn initialize_without_pcs() -> Self {
        Self::new_inner(None)
    }

    fn new_inner(pcs_prover: Option<PCS>) -> Self {
        Self {
            transcript: Vec::new(),
            challenger: GC::default_challenger(),
            pcs_prover,
            oracles: Vec::new(),
            pcs_proofs: Vec::new(),
            replay_sent: Vec::new(),
            replay_sent_cursor: 0,
            replay_challenges: Vec::new(),
            replay_challenge_cursor: 0,
            replay_oracle_cursor: 0,
            pcs_claim_made: false,
        }
    }

    /// Finalize the proof: consume the context and emit the raw transcript, oracle
    /// commits, and the stacked-basefold opening proofs already produced eagerly at each
    /// `assert_mle_multi_eval` call. `rng` is unused — transparent mode doesn't mask.
    pub fn prove<RNG: rand::CryptoRng + rand::Rng>(
        self,
        _rng: &mut RNG,
    ) -> Result<TransparentProof<GC, PCS::Proof>, TransparentProveError<PCS::ProverError>>
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
    {
        let oracle_commits = self
            .oracles
            .iter()
            .map(|o| (o.commitment, o.num_encoding_variables, o.log_num_polynomials))
            .collect();

        // Openings were discharged eagerly at each `assert_mle_multi_eval` call, in order.
        Ok(TransparentProof {
            transcript: self.transcript,
            oracle_commits,
            pcs_proofs: self.pcs_proofs,
        })
    }

    /// Eagerly opens the given oracles at `point` (all sharing it) through the base PCS, advancing
    /// the Fiat-Shamir challenger over the opening, and records the proof. `claimed_evals` are the
    /// per-oracle evaluations the protocol claims (bound by the opening). All oracles must share the
    /// same shape (encoding width + `log_num_polynomials`).
    fn open_mle_commitment(
        &mut self,
        oracle_indices: &[usize],
        claimed_evals: &[GC::EF],
        point: &Point<GC::EF>,
    ) -> Result<(), TransparentProveError<PCS::ProverError>>
    where
        PCS::ProverData: Clone,
    {
        let log_stacking_height = self.oracles[oracle_indices[0]].num_encoding_variables as usize;
        let commit_datas: Vec<&TransparentCommitData<GC, PCS>> = oracle_indices
            .iter()
            .map(|&idx| self.oracles[idx].prover_data.as_ref().expect("oracle data missing"))
            .collect();
        let pcs_prover = self.pcs_prover.as_ref().ok_or(TransparentProveError::NoPcsProver)?;
        let proof = pcs::open(
            pcs_prover,
            &commit_datas,
            point,
            claimed_evals,
            log_stacking_height,
            &mut self.challenger,
        )
        .map_err(TransparentProveError::Pcs)?;
        self.pcs_proofs.push(proof);
        Ok(())
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
/// * `num_encoding_variables` — number of variables per stacked column (encoding width). Every
///   subsequent [`commit_mle`](crate::compiler::SendingCtx::commit_mle) /
///   [`read_oracle`](crate::compiler::ReadingCtx::read_oracle) call must use a matching
///   `num_encoding_variables`; the number of stacked columns is inferred per commit from the MLE
///   size, so no fixed batch size is needed.
#[allow(clippy::type_complexity)]
pub fn initialize_transparent_prover_and_verifier<GC, MK>(
    num_expected_commitments: usize,
    num_encoding_variables: u32,
) -> (BasefoldTransparentProver<GC, MK>, super::BasefoldTransparentVerifier<GC>)
where
    GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
    MK: ComputeTcsOpenings<GC, CpuBackend> + Default,
{
    let basefold_verifier =
        BasefoldVerifier::<GC>::new(FriConfig::default_fri_config(), num_expected_commitments);
    let basefold_prover = BasefoldProver::<GC, MK>::new(&basefold_verifier);
    // `batch_size` only parameterizes the stacked interleaving commit, which the base-PCS
    // (`BatchPcsProver`) path never touches; any value works here.
    let prover = StackedPcsProver::new(basefold_prover, num_encoding_variables, 1);
    let verifier = StackedPcsVerifier::new(basefold_verifier, num_encoding_variables);
    (prover, verifier)
}

// ============================================================================
// ConstraintCtx: polynomial-identity asserts are no-ops; MLE-eval asserts are
//                discharged eagerly into a stacked-basefold opening at the call site.
// ============================================================================

impl<GC, PCS> ConstraintCtx for TransparentProverCtx<GC, PCS>
where
    GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
    PCS: BatchPcsProver<GC>,
    // The eager opening clones each oracle's base prover data (cheap — `Arc`/`Message`-backed).
    PCS::ProverData: Clone,
{
    type Field = GC::F;
    type Extension = GC::EF;
    type Expr = GC::EF;
    type Challenge = GC::EF;
    type MleCommit = TransparentMleOracle;
    // MLE-eval openings are produced eagerly, so an assertion can fail here (missing PCS prover or
    // a base-PCS prover error). The plain `assert_zero` only no-ops and returns `Ok(())`.
    type AssertError = TransparentProveError<PCS::ProverError>;

    fn assert_zero(&mut self, _expr: Self::Expr) -> Result<(), Self::AssertError> {
        Ok(())
    }

    fn assert_mle_multi_eval(
        &mut self,
        claims: Vec<(Self::MleCommit, Self::Expr)>,
        point: &Point<Self::Challenge>,
    ) -> Result<(), Self::AssertError> {
        self.pcs_claim_made = true;
        // Eagerly open all the claims' oracles at the shared point, binding their claimed evals.
        let oracle_indices: Vec<usize> = claims.iter().map(|(oracle, _)| oracle.idx).collect();
        let claimed_evals: Vec<GC::EF> = claims.iter().map(|(_, eval)| *eval).collect();
        self.open_mle_commitment(&oracle_indices, &claimed_evals, point)
    }

    fn assert_mle_multi_eval_with_oracle<O: OracleEval<Self::Expr, Self::Expr>>(
        &mut self,
        _claims: Vec<MleEvalClaim<Self::MleCommit, Self::Expr, O>>,
        _point: &Point<Self::Challenge>,
    ) -> Result<(), Self::AssertError> {
        // The general (custom-combiner / cross-commitment) form is expressed over PCS column
        // sub-evaluations, which the transparent backend (direct MLE evaluation, no stacked-column
        // opening) does not surface. Only the default-decomposition `assert_mle_multi_eval` /
        // `assert_mle_eval` paths (which this backend implements directly) are supported here.
        unimplemented!(
            "custom-oracle / cross-commitment MLE-eval claims are not supported by the transparent \
             backend"
        )
    }
}

// ============================================================================
// SendingCtx: push values onto the transcript, observe them, commit MLEs, and
// finalize the proof.
// ============================================================================

impl<GC, PCS> SendingCtx for TransparentProverCtx<GC, PCS>
where
    GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
    PCS: BatchPcsProver<GC>,
    PCS::ProverData: Clone,
{
    type CommitError = TransparentCommitError<PCS::ProverError>;

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

    fn num_encoding_variables(&self) -> u32 {
        self.pcs_prover
            .as_ref()
            .expect("num_encoding_variables requires a PCS-backed context")
            .num_encoding_variables()
    }

    /// Commits a **pre-stacked** block-column MLE (`mle[0]` is the `[2^num_encoding_variables,
    /// num_columns]` tensor, column `ℓ` = the block `f_ℓ`) through the base PCS. `rng` is unused —
    /// transparent mode doesn't mask.
    fn commit_mle<RNG: rand::CryptoRng + rand::Rng>(
        &mut self,
        mle: Message<Mle<GC::F>>,
        _rng: &mut RNG,
    ) -> Result<Self::MleCommit, Self::CommitError>
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::F>,
    {
        let pcs_prover = self.pcs_prover.as_ref().ok_or(TransparentCommitError::NoPcsProver)?;
        let num_encoding_variables = pcs_prover.num_encoding_variables();
        // Pre-stacked data components: every component's columns are over exactly
        // `num_encoding_variables` variables; their widths sum to the commitment's column count.
        let mut num_data_cols = 0usize;
        for component in mle.iter() {
            let num_variables = component.num_variables();
            if num_variables != num_encoding_variables {
                return Err(TransparentCommitError::WrongEncodingWidth {
                    num_variables,
                    num_encoding_variables,
                });
            }
            num_data_cols += component.num_polynomials();
        }
        let log_num_polynomials = num_data_cols.next_power_of_two().trailing_zeros();
        let (commitment, commit_data) =
            pcs::commit(pcs_prover, mle).map_err(TransparentCommitError::Pcs)?;
        self.challenger.observe(commitment);
        let idx = self.oracles.len();
        self.oracles.push(OracleEntry {
            commitment,
            num_encoding_variables,
            log_num_polynomials,
            prover_data: Some(commit_data),
        });
        // No replay buffer needed: `read_oracle` reconstructs this handle from a
        // cursor, since indices are assigned in commit order.
        Ok(TransparentMleOracle { idx })
    }
}

// ============================================================================
// ReadingCtx impl
// ============================================================================
//
// Pure record/replay over the buffers populated during the `SendingCtx` pass.
// Like the ZK prover, these methods never touch the challenger — challenges are
// replayed from `replay_challenges` — so the post-compute Fiat-Shamir state that
// `prove()` uses to derive PCS openings is left untouched.

impl<GC, PCS> ReadingCtx for TransparentProverCtx<GC, PCS>
where
    GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
    PCS: BatchPcsProver<GC>,
    PCS::ProverData: Clone,
{
    fn read_exact(&mut self, buf: &mut [Self::Expr]) -> Result<(), TranscriptReadError> {
        if self.pcs_claim_made {
            return Err(TranscriptReadError::ReadAfterPcsClaim);
        }
        let end = self.replay_sent_cursor + buf.len();
        let slice = self
            .replay_sent
            .get(self.replay_sent_cursor..end)
            .ok_or(TranscriptReadError::TranscriptExhausted)?;
        buf.copy_from_slice(slice);
        self.replay_sent_cursor = end;
        Ok(())
    }

    fn read_oracle(&mut self, _num_variables: u32) -> Option<Self::MleCommit> {
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
