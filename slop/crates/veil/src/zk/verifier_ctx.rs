use slop_algebra::{AbstractField, Dorroh};
use slop_challenger::FieldChallenger;
use slop_commit::Rounds;
use slop_multilinear::{LinearOracleEval, OracleEval, Point};
use slop_stacked::{stacked_oracle_eval, stacked_reduced_point};

use crate::compiler::{ConstraintCtx, MleEvalClaim, ReadingCtx, TranscriptReadError};
use crate::zk::inner::{
    ConstraintContextInner, ConstraintContextInnerExt, ExpressionIndex, MleCommitmentIndex,
    ZkCnstrAndReadingCtxInner, ZkPcsVerifier, ZkVerificationContext, ZkVerifierError,
};
use crate::zk::{ZkIopCtx, ZkProof};

pub struct ZkVerifierCtx<GC: ZkIopCtx, V: ZkPcsVerifier<GC>> {
    inner: ZkVerificationContext<GC, V::Proof>,
    pcs_verifier: Option<V>,
    /// Set once any MLE-eval claim (eager PCS opening) has been verified. Guards against further
    /// transcript reads, which would read past the (terminal) PCS openings.
    pcs_claim_made: bool,
}

impl<GC: ZkIopCtx, V: ZkPcsVerifier<GC>> ZkVerifierCtx<GC, V> {
    pub fn init(proof: ZkProof<GC, V::Proof>, pcs_verifier: Option<V>) -> Self {
        let inner = proof.open();
        Self { inner, pcs_verifier, pcs_claim_made: false }
    }

    /// Verify after consuming the transcript and building all constraints.
    ///
    /// MLE-eval openings are verified eagerly at the `assert_mle_eval` call site (which returns any
    /// failure there); this finalizes the linear and multiplicative constraints.
    pub fn verify(self) -> Result<(), ZkVerifierError> {
        self.inner.verify()
    }
}

/// An abstract representation of a transcript extension field element.
///
/// Either a concrete field constant (`Dorroh::Constant`) or an opaque expression index
/// into the verifier transcript (`Dorroh::Element`).
#[allow(type_alias_bounds)]
pub type TranscriptElement<GC: ZkIopCtx, P = ()> =
    Dorroh<GC::EF, ExpressionIndex<GC::EF, ZkVerificationContext<GC, P>>>;

#[derive(Clone, Copy)]
pub struct MleCommit {
    pub(crate) inner: MleCommitmentIndex,
}

/// `(reduced_point, default-decomposition claims)` — the output of [`default_stacked_eval_claims`].
type DefaultStackedClaims<Commit, Expr, EF> =
    (Point<EF>, Vec<MleEvalClaim<Commit, Expr, LinearOracleEval<EF>>>);

/// Builds the default stacked decomposition for a batch of single-commitment eval claims (the
/// `assert_mle_multi_eval` path, shared by the prover and verifier contexts).
///
/// Returns the shared reduced opening point (the encoding coords) and one [`MleEvalClaim`] per
/// `(commitment, eval)`, each combining its commitment's columns with the eq-coefficient stacking
/// oracle. `log_num_cols` is the (batch-shared) commitment column-count log.
pub(crate) fn default_stacked_eval_claims<Commit, Expr, EF: AbstractField + Copy>(
    point: &Point<EF>,
    log_num_cols: usize,
    claims: Vec<(Commit, Expr)>,
) -> DefaultStackedClaims<Commit, Expr, EF> {
    let log_stacking_height = point.dimension() - log_num_cols;
    let reduced_point = stacked_reduced_point(point, log_stacking_height);
    let oracle_eval = stacked_oracle_eval(point, log_stacking_height);
    let eval_claims = claims
        .into_iter()
        .map(|(commit, eval)| MleEvalClaim {
            commits: Rounds { rounds: vec![commit] },
            claimed_eval: eval,
            oracle_eval: oracle_eval.clone(),
        })
        .collect();
    (reduced_point, eval_claims)
}

// ============================================================================
// Conversion helper: HiddenElement → VerifierValue
// ============================================================================

fn into_verifier_value<GC: ZkIopCtx, P>(
    elem: TranscriptElement<GC, P>,
    ctx: &mut ZkVerificationContext<GC, P>,
) -> ExpressionIndex<GC::EF, ZkVerificationContext<GC, P>> {
    match elem {
        Dorroh::Constant(f) => ctx.cst(f),
        Dorroh::Element(e) => e,
    }
}

// ============================================================================
// ConstraintCtx impl
// ============================================================================

impl<GC: ZkIopCtx, V: ZkPcsVerifier<GC>> ConstraintCtx for ZkVerifierCtx<GC, V> {
    type Field = GC::F;
    type Extension = GC::EF;
    type Expr = TranscriptElement<GC, V::Proof>;
    type Challenge = GC::EF;
    type MleCommit = MleCommit;
    // MLE-eval openings are verified eagerly, so an assertion can fail here (a failed PCS proof or
    // a missing PCS verifier). The plain `assert_zero`/`assert_a_times_b_equals_c` only queue
    // constraints and never fail, so they return `Ok(())`.
    type AssertError = ZkVerifierError;

    fn assert_zero(
        &mut self,
        expr: TranscriptElement<GC, V::Proof>,
    ) -> Result<(), Self::AssertError> {
        let idx = into_verifier_value(expr, &mut self.inner);
        self.inner.assert_zero(idx);
        Ok(())
    }

    fn assert_a_times_b_equals_c(
        &mut self,
        a: TranscriptElement<GC, V::Proof>,
        b: TranscriptElement<GC, V::Proof>,
        c: TranscriptElement<GC, V::Proof>,
    ) -> Result<(), Self::AssertError> {
        let ai = into_verifier_value(a, &mut self.inner);
        let bi = into_verifier_value(b, &mut self.inner);
        let ci = into_verifier_value(c, &mut self.inner);
        self.inner.assert_a_times_b_equals_c(ai, bi, ci);
        Ok(())
    }

    fn assert_mle_multi_eval(
        &mut self,
        claims: Vec<(MleCommit, TranscriptElement<GC, V::Proof>)>,
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
        claims: Vec<MleEvalClaim<MleCommit, TranscriptElement<GC, V::Proof>, O>>,
        point: &Point<GC::EF>,
    ) -> Result<(), Self::AssertError> {
        self.pcs_claim_made = true;

        // Open all the claims' commitments (flattened in claim order) together at `point` in one
        // base proof.
        let commitment_indices: Rounds<MleCommitmentIndex> =
            claims.iter().flat_map(|c| c.commits.iter().map(|commit| commit.inner)).collect();
        let per_commit_cols = match self.pcs_verifier.as_ref() {
            Some(pcs_verifier) => {
                self.inner.verify_mle_eval(pcs_verifier, commitment_indices, point)?
            }
            None => return Err(ZkVerifierError::NoPcsVerifier),
        };

        // Hand each claim back its commitments' columns (a `Rounds` in `commits` order, the idiom
        // the combiner consumes) and constrain the combined value to the claimed eval.
        let mut cols_iter = per_commit_cols.into_iter();
        for claim in claims {
            let claim_cols: Vec<Vec<TranscriptElement<GC, V::Proof>>> = claim
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
            let rounds: Rounds<&[TranscriptElement<GC, V::Proof>]> =
                claim_cols.iter().map(|c| c.as_slice()).collect();
            let combined = claim.oracle_eval.evaluate_oracle(rounds, 0);
            self.assert_zero(claim.claimed_eval - combined)?;
        }
        Ok(())
    }
}

// ============================================================================
// ReadingCtx impl
// ============================================================================

impl<GC: ZkIopCtx, V: ZkPcsVerifier<GC>> ReadingCtx for ZkVerifierCtx<GC, V> {
    fn read_exact(&mut self, buf: &mut [Self::Expr]) -> Result<(), TranscriptReadError> {
        if self.pcs_claim_made {
            return Err(TranscriptReadError::ReadAfterPcsClaim);
        }
        // If we only want one element, use a more efficient method that avoids allocations.
        if buf.len() == 1 {
            buf[0] = Dorroh::Element(self.inner.read_one()?);
            return Ok(());
        }
        // Otherwise, read a vector and copy.
        let values = self.inner.read_next(buf.len())?;
        for (b, value) in buf.iter_mut().zip(values) {
            *b = Dorroh::Element(value);
        }
        Ok(())
    }

    fn read_oracle(&mut self, num_variables: u32) -> Option<MleCommit> {
        let num_encoding_variables = self.pcs_verifier.as_ref()?.num_encoding_variables();
        let log_num_polynomials = num_variables.checked_sub(num_encoding_variables)?;
        self.inner
            .read_next_pcs_commitment(num_encoding_variables as usize, log_num_polynomials as usize)
            .map(|idx| MleCommit { inner: idx })
    }

    fn sample(&mut self) -> GC::EF {
        self.inner.with_challenger(|c| c.sample_ext_element())
    }
}
