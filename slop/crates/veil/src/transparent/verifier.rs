use slop_algebra::{Field, TwoAdicField};
use slop_challenger::{CanObserve, FieldChallenger, IopCtx};
use slop_multilinear::{BatchPcsVerifier, OracleEval, Point};
use slop_stacked::StackedPcsVerifier;
use thiserror::Error;

use crate::compiler::{ConstraintCtx, MleEvalClaim, ReadingCtx, TranscriptReadError};
use crate::transparent::pcs;
use crate::transparent::prover::TransparentProof;

/// Basefold specialization of the transparent backend's base PCS verifier: the Basefold verifier
/// pinned to its fixed encoding width (= stacking height). Verifier-side mirror of
/// [`TransparentPcsProver`](crate::transparent::TransparentPcsProver).
#[allow(type_alias_bounds)]
pub type BasefoldTransparentVerifier<GC: IopCtx> = StackedPcsVerifier<GC>;

/// Basefold specialization of [`TransparentVerifierCtx`] (the context used in tests/examples).
#[allow(type_alias_bounds)]
pub type BasefoldTransparentVerifierCtx<GC: IopCtx> =
    TransparentVerifierCtx<GC, StackedPcsVerifier<GC>>;

/// Opaque handle the verifier hands out for each committed oracle. The digest and
/// shape live in [`TransparentVerifierCtx::oracle_commits`]; this is just an index.
#[derive(Clone, Copy, Debug)]
pub struct TransparentVerifierOracle {
    /// Index into `TransparentVerifierCtx::oracle_commits`.
    idx: usize,
}

/// Verifier error. `E` is the base PCS verifier's error type.
#[derive(Debug, Error)]
pub enum VerifyError<E: std::error::Error + 'static> {
    #[error("assertion failed: expression did not evaluate to zero (got {0})")]
    AssertZeroFailed(String),
    #[error("PCS proof exhausted: an MLE-eval opening was asserted but no proof remained")]
    PcsProofExhausted,
    #[error("not all PCS proofs were consumed: {consumed} consumed of {available}")]
    PcsProofsUnconsumed { consumed: usize, available: usize },
    #[error(
        "an MLE-eval opening was asserted but the verifier was constructed without a PCS verifier"
    )]
    MissingPcsVerifier,
    #[error(transparent)]
    PcsError(E),
}

/// Transparent verifier context.
///
/// There is no masking and no compiled constraint language in the transparent
/// backend — `Expr` is just the underlying extension-field element. Every
/// `assert_zero` / `assert_a_times_b_equals_c` call eagerly evaluates its
/// argument and fails on a non-zero value; MLE-eval claims are verified
/// **eagerly** at the `assert_mle_*` call site against the next stacked-basefold
/// PCS proof (matching the ZK backend). [`Self::verify`] then only checks that
/// every PCS proof was consumed.
pub struct TransparentVerifierCtx<GC: IopCtx, PCS: BatchPcsVerifier<GC>> {
    // From the proof.
    transcript: Vec<Vec<GC::EF>>,
    /// One entry per committed oracle: `(digest, num_encoding_variables, log_num_polynomials)`.
    /// Shapes come from the proof; `read_oracle` checks them against the caller's
    /// requested shape.
    oracle_commits: Vec<(GC::Digest, u32, u32)>,
    pcs_proofs: Vec<PCS::Proof>,

    // Traversal cursors.
    /// Next transcript message to read.
    read_cursor: usize,
    /// Next commitment to hand out as an oracle.
    oracle_cursor: usize,
    /// Next PCS proof to consume, advanced once per eager MLE-eval verification.
    pcs_proof_cursor: usize,

    // Fiat-Shamir.
    challenger: GC::Challenger,

    // PCS verifier (`None` if the protocol emitted no MLE claims).
    pcs_verifier: Option<PCS>,

    /// Set once any MLE-eval claim has been verified. Guards against further transcript reads,
    /// which would read past the (terminal) PCS openings.
    pcs_claim_made: bool,
}

impl<GC: IopCtx, PCS: BatchPcsVerifier<GC>> TransparentVerifierCtx<GC, PCS> {
    /// Build a verifier context from a raw transparent proof plus the base PCS verifier config used
    /// on the prover side.
    pub fn new(proof: TransparentProof<GC, PCS::Proof>, pcs_verifier: Option<PCS>) -> Self {
        Self {
            transcript: proof.transcript,
            oracle_commits: proof.oracle_commits,
            pcs_proofs: proof.pcs_proofs,
            read_cursor: 0,
            oracle_cursor: 0,
            pcs_proof_cursor: 0,
            challenger: GC::default_challenger(),
            pcs_verifier,
            pcs_claim_made: false,
        }
    }
}

// ============================================================================
// ConstraintCtx
// ============================================================================

impl<GC, PCS> ConstraintCtx for TransparentVerifierCtx<GC, PCS>
where
    GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
    PCS: BatchPcsVerifier<GC, Commitment = GC::Digest>,
    PCS::Proof: Clone,
{
    type Field = GC::F;
    type Extension = GC::EF;
    type Expr = GC::EF;
    type Challenge = GC::EF;
    type MleCommit = TransparentVerifierOracle;
    // MLE-eval openings are verified eagerly, so an assertion can fail with a PCS error here. The
    // `assert_zero` arm fails with [`VerifyError::AssertZeroFailed`].
    type AssertError = VerifyError<PCS::VerifierError>;

    fn assert_zero(&mut self, expr: Self::Expr) -> Result<(), Self::AssertError> {
        if expr.is_zero() {
            Ok(())
        } else {
            Err(VerifyError::AssertZeroFailed(format!("{expr:?}")))
        }
    }

    /// Eagerly verifies the next opening: the base PCS binds the (α-batched, stacking-combined)
    /// virtual oracle to the claimed evals — so the per-oracle eval check is the base PCS's job, not
    /// a separate cross-check.
    fn assert_mle_multi_eval(
        &mut self,
        claims: Vec<(Self::MleCommit, Self::Expr)>,
        point: &Point<Self::Challenge>,
    ) -> Result<(), Self::AssertError> {
        self.pcs_claim_made = true;

        // Consume the next eager opening proof (produced in the same order by the prover).
        let cursor = self.pcs_proof_cursor;
        let pcs_proof = self.pcs_proofs.get(cursor).ok_or(VerifyError::PcsProofExhausted)?.clone();
        self.pcs_proof_cursor = cursor + 1;
        let pcs_verifier = self.pcs_verifier.as_ref().ok_or(VerifyError::MissingPcsVerifier)?;

        let commits: Vec<GC::Digest> =
            claims.iter().map(|(o, _)| self.oracle_commits[o.idx].0).collect();
        let claimed_evals: Vec<GC::EF> = claims.iter().map(|(_, eval)| *eval).collect();
        // All oracles in a batch share the same shape; take `num_encoding_variables` from the first.
        let log_stacking_height = self.oracle_commits[claims[0].0.idx].1 as usize;

        pcs::verify(
            pcs_verifier,
            &commits,
            point,
            &claimed_evals,
            log_stacking_height,
            &pcs_proof,
            &mut self.challenger,
        )
        .map_err(VerifyError::PcsError)?;
        Ok(())
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
// ReadingCtx
// ============================================================================

impl<GC, PCS> ReadingCtx for TransparentVerifierCtx<GC, PCS>
where
    GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
    PCS: BatchPcsVerifier<GC, Commitment = GC::Digest>,
    PCS::Proof: Clone,
{
    fn read_exact(&mut self, buf: &mut [Self::Expr]) -> Result<(), TranscriptReadError> {
        if self.pcs_claim_made {
            return Err(TranscriptReadError::ReadAfterPcsClaim);
        }
        let message = self
            .transcript
            .get(self.read_cursor)
            .ok_or(TranscriptReadError::TranscriptExhausted)?;
        if message.len() != buf.len() {
            return Err(TranscriptReadError::TranscriptReadMismatch {
                expected: buf.len(),
                got: message.len(),
            });
        }

        //If everything is shaped well, copy the message into the buffer, observe each
        // value on the challenger (mirroring the prover's `send_value[s]`), and advance
        // the cursor.
        for (b, v) in buf.iter_mut().zip(message) {
            *b = *v;
            self.challenger.observe_ext_element(*v);
        }
        self.read_cursor += 1;
        Ok(())
    }

    fn read_oracle(&mut self, num_variables: u32) -> Option<Self::MleCommit> {
        // The PCS's fixed encoding width pins the expected per-oracle shape; subtract it
        // from the declared total to recover the expected number of stacked polynomials.
        let num_encoding_variables = self.pcs_verifier.as_ref()?.num_encoding_variables();
        let log_num_polynomials = num_variables.checked_sub(num_encoding_variables)?;
        let idx = self.oracle_cursor;
        let (digest, proof_num_enc, proof_log_num) = *self.oracle_commits.get(idx)?;
        if proof_num_enc != num_encoding_variables || proof_log_num != log_num_polynomials {
            return None;
        }
        self.oracle_cursor += 1;
        self.challenger.observe(digest);
        Some(TransparentVerifierOracle { idx })
    }

    fn sample(&mut self) -> Self::Challenge {
        self.challenger.sample_ext_element()
    }
}

// ============================================================================
// verify()
// ============================================================================

impl<GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>, Verifier: BatchPcsVerifier<GC>>
    TransparentVerifierCtx<GC, Verifier>
{
    /// Finalizes verification. MLE-eval openings are verified eagerly at each `assert_mle_*` call
    /// site (returning a [`VerifyError`] there); this only checks that every PCS proof carried in
    /// the proof was consumed by an opening (no extra/dangling openings).
    pub fn verify(self) -> Result<(), VerifyError<Verifier::VerifierError>> {
        let consumed = self.pcs_proof_cursor;
        let available = self.pcs_proofs.len();
        if consumed != available {
            return Err(VerifyError::PcsProofsUnconsumed { consumed, available });
        }
        Ok(())
    }
}
