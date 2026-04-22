use std::cell::RefCell;
use std::rc::Rc;

use slop_algebra::{AbstractField, Field, TwoAdicField};
use slop_basefold::BasefoldVerifier;
use slop_challenger::{CanObserve, FieldChallenger, IopCtx};
use slop_multilinear::{Mle, Point};
use slop_stacked::{StackedBasefoldProof, StackedPcsVerifier, StackedVerifierError};
use thiserror::Error;

use crate::compiler::{ConstraintCtx, ReadingCtx, TranscriptExhaustedError};
use crate::transparent::expression::{
    evaluate_expr, evaluate_pool, Element, Expr, ExprNode, ExpressionPool,
};
use crate::transparent::prover::TransparentProof;

/// Opaque handle the verifier hands out for each committed oracle. Carries enough
/// shape information to look up the commitment and compute the PCS "round area" at
/// verify time.
#[derive(Clone, Copy, Debug)]
pub struct TransparentVerifierOracle {
    /// Index into `TransparentVerifierCtx::oracle_commits`.
    idx: usize,
    num_encoding_variables: u32,
    log_num_polynomials: u32,
}

impl TransparentVerifierOracle {
    fn num_variables(&self) -> u32 {
        self.num_encoding_variables + self.log_num_polynomials
    }
}

/// One pending MLE-eval claim group: all oracles are opened at the same point.
/// Paired with one [`StackedBasefoldProof`] from the prover.
struct MleClaimGroup<EF> {
    oracles: Vec<TransparentVerifierOracle>,
    eval_exprs: Vec<Expr<EF>>,
    point: Point<EF>,
}

/// A pending `a * b = c` claim, stored between `assert_a_times_b_equals_c` and `verify`.
type MulClaim<EF> = (Expr<EF>, Expr<EF>, Expr<EF>);

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("assertion failed: asserted expression did not evaluate to zero")]
    AssertZeroFailed,
    #[error("a * b = c assertion failed")]
    AssertMulFailed,
    #[error("number of PCS proofs ({expected}) does not match number of MLE eval claim groups ({actual})")]
    PcsProofCountMismatch { expected: usize, actual: usize },
    #[error(transparent)]
    PcsError(
        StackedVerifierError<
            slop_basefold::BaseFoldVerifierError<slop_merkle_tree::MerkleTreeTcsError>,
        >,
    ),
}

/// Transparent verifier context.
///
/// Stores the incoming transcript + oracle commitments + PCS proofs, tracks an
/// expression AST for any constraints the protocol emits, and records MLE-eval
/// claim groups for PCS-level verification at the end.
pub struct TransparentVerifierCtx<GC: IopCtx> {
    // ---- from the proof ----
    transcript: Vec<Vec<GC::EF>>,
    oracle_commits: Vec<GC::Digest>,
    pcs_proofs: Vec<StackedBasefoldProof<GC>>,

    // ---- traversal cursors ----
    /// Next transcript element to read, as `(group_idx, local_idx)`.
    read_cursor: (usize, usize),
    /// Next commitment to hand out as an oracle.
    oracle_cursor: usize,

    // ---- Fiat-Shamir ----
    challenger: GC::Challenger,

    // ---- expression AST ----
    pool: Rc<RefCell<ExpressionPool<GC::EF>>>,

    // ---- constraint claims ----
    zero_claims: Vec<Expr<GC::EF>>,
    mul_claims: Vec<MulClaim<GC::EF>>,
    mle_claims: Vec<MleClaimGroup<GC::EF>>,

    // ---- oracle shapes (parallel to oracle_commits) ----
    oracle_shapes: Vec<(u32, u32)>,

    // ---- PCS verifier (optional: `None` if the protocol emitted no MLE claims) ----
    pcs_verifier: Option<StackedPcsVerifier<GC>>,
}

impl<GC: IopCtx> TransparentVerifierCtx<GC> {
    /// Build a verifier context from a raw transparent proof plus the stacked-basefold
    /// verifier config used on the prover side.
    pub fn new(proof: TransparentProof<GC>, pcs_verifier: Option<StackedPcsVerifier<GC>>) -> Self {
        Self {
            transcript: proof.transcript,
            oracle_commits: proof.oracle_commits,
            pcs_proofs: proof.pcs_proofs,
            read_cursor: (0, 0),
            oracle_cursor: 0,
            challenger: GC::default_challenger(),
            pool: Rc::new(RefCell::new(ExpressionPool::default())),
            zero_claims: Vec::new(),
            mul_claims: Vec::new(),
            mle_claims: Vec::new(),
            oracle_shapes: Vec::new(),
            pcs_verifier,
        }
    }

    /// Advance the read cursor by one and return the position that was read.
    /// Panics if the transcript is exhausted.
    fn advance_read_cursor(&mut self) -> (usize, usize) {
        while self.read_cursor.0 < self.transcript.len() {
            let (g, l) = self.read_cursor;
            if l < self.transcript[g].len() {
                self.read_cursor.1 += 1;
                return (g, l);
            }
            self.read_cursor.0 += 1;
            self.read_cursor.1 = 0;
        }
        panic!("transcript exhausted");
    }

    fn push_var(&mut self) -> Element<GC::EF> {
        let (g, l) = self.advance_read_cursor();
        let idx = self.pool.borrow_mut().push(ExprNode::Var(g, l));
        Element::new(self.pool.clone(), idx)
    }
}

// ============================================================================
// ConstraintCtx
// ============================================================================

impl<GC: IopCtx> ConstraintCtx for TransparentVerifierCtx<GC> {
    type Field = GC::F;
    type Extension = GC::EF;
    type Expr = Expr<GC::EF>;
    type Challenge = GC::EF;
    type MleOracle = TransparentVerifierOracle;

    fn assert_zero(&mut self, expr: Self::Expr) {
        self.zero_claims.push(expr);
    }

    fn assert_a_times_b_equals_c(&mut self, a: Self::Expr, b: Self::Expr, c: Self::Expr) {
        self.mul_claims.push((a, b, c));
    }

    fn assert_mle_multi_eval(
        &mut self,
        claims: Vec<(Self::MleOracle, Self::Expr)>,
        point: Point<Self::Challenge>,
    ) {
        let mut oracles = Vec::with_capacity(claims.len());
        let mut eval_exprs = Vec::with_capacity(claims.len());
        for (oracle, eval) in claims {
            oracles.push(oracle);
            eval_exprs.push(eval);
        }
        self.mle_claims.push(MleClaimGroup { oracles, eval_exprs, point });
    }
}

// ============================================================================
// ReadingCtx
// ============================================================================

impl<GC: IopCtx> ReadingCtx for TransparentVerifierCtx<GC> {
    fn read_exact(&mut self, buf: &mut [Self::Expr]) -> Result<(), TranscriptExhaustedError> {
        for slot in buf.iter_mut() {
            *slot = Expr::Node(self.push_var());
            // Observe the value the prover committed to at that slot in the challenger.
            let (g, l) = {
                // Grab the just-pushed Var node to get its (g, l).
                match self.pool.borrow().nodes().last() {
                    Some(ExprNode::Var(g, l)) => (*g, *l),
                    _ => unreachable!("push_var pushed a non-Var node"),
                }
            };
            self.challenger.observe_ext_element(self.transcript[g][l]);
        }
        Ok(())
    }

    fn read_oracle(
        &mut self,
        num_encoding_variables: u32,
        log_num_polynomials: u32,
    ) -> Option<Self::MleOracle> {
        if self.oracle_cursor >= self.oracle_commits.len() {
            return None;
        }
        let idx = self.oracle_cursor;
        self.oracle_cursor += 1;
        self.challenger.observe(self.oracle_commits[idx]);
        self.oracle_shapes.push((num_encoding_variables, log_num_polynomials));
        Some(TransparentVerifierOracle { idx, num_encoding_variables, log_num_polynomials })
    }

    fn sample(&mut self) -> Self::Challenge {
        self.challenger.sample_ext_element()
    }
}

// ============================================================================
// verify()
// ============================================================================

impl<GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>> TransparentVerifierCtx<GC> {
    /// Run the full verification pass:
    ///
    /// 1. Evaluate every node in the expression pool (single linear sweep).
    /// 2. Check every `assert_zero` claim evaluates to zero.
    /// 3. Check every `a*b=c` claim is consistent.
    /// 4. For each recorded MLE-eval claim group, dispatch to the stacked-basefold
    ///    PCS verifier using the matching `pcs_proofs[i]`.
    pub fn verify(mut self) -> Result<(), VerifyError> {
        // 1. Flat evaluation of the expression pool.
        let pool = self.pool.borrow();
        let values = evaluate_pool(&pool, &self.transcript);
        drop(pool);

        // 2. Check asserted-zero claims.
        for expr in &self.zero_claims {
            let v = evaluate_expr(expr, &values);
            if !v.is_zero() {
                return Err(VerifyError::AssertZeroFailed);
            }
        }

        // 3. Check `a*b=c` claims.
        for (a, b, c) in &self.mul_claims {
            let av = evaluate_expr(a, &values);
            let bv = evaluate_expr(b, &values);
            let cv = evaluate_expr(c, &values);
            if av * bv != cv {
                return Err(VerifyError::AssertMulFailed);
            }
        }

        // 4. MLE-eval claim groups → PCS checks.
        if !self.mle_claims.is_empty() {
            if self.pcs_proofs.len() != self.mle_claims.len() {
                return Err(VerifyError::PcsProofCountMismatch {
                    expected: self.mle_claims.len(),
                    actual: self.pcs_proofs.len(),
                });
            }
            let pcs_verifier = self
                .pcs_verifier
                .as_ref()
                .expect("MLE-eval claims exist but no PCS verifier was configured");

            for (group, pcs_proof) in self.mle_claims.iter().zip(&self.pcs_proofs) {
                // Assemble the inputs that `verify_trusted_evaluation` expects.
                let commits: Vec<GC::Digest> =
                    group.oracles.iter().map(|o| self.oracle_commits[o.idx]).collect();
                let round_areas: Vec<usize> = group
                    .oracles
                    .iter()
                    .map(|o| {
                        (1usize << o.num_variables())
                            .next_multiple_of(1usize << pcs_verifier.log_stacking_height)
                    })
                    .collect();

                // The batched `evaluation_claim` is the combined MLE of the proof's
                // `batch_evaluations`, evaluated at `batch_point` — the prefix of
                // `eval_point` that addresses across stacked polys (see
                // `benchmarking/common.rs::run_standard_hadamard`).
                let eval_point = group.point.clone();
                let log_stack = pcs_verifier.log_stacking_height as usize;
                let (batch_point, _) = eval_point.split_at(eval_point.dimension() - log_stack);
                let batch_evals_mle: Mle<GC::EF> =
                    pcs_proof.batch_evaluations.iter().flatten().cloned().collect();
                let eval_claim = batch_evals_mle.blocking_eval_at(&batch_point)[0];

                pcs_verifier
                    .verify_trusted_evaluation(
                        &commits,
                        &round_areas,
                        &eval_point,
                        pcs_proof,
                        eval_claim,
                        &mut self.challenger,
                    )
                    .map_err(VerifyError::PcsError)?;
            }
        }

        Ok(())
    }
}

// Convenience helper so callers can build a `StackedPcsVerifier` with a default
// basefold config.
#[allow(dead_code)]
fn default_pcs_verifier<GC: IopCtx>(log_stacking_height: u32) -> StackedPcsVerifier<GC> {
    StackedPcsVerifier::new(
        BasefoldVerifier::<GC>::new(slop_basefold::FriConfig::default_fri_config(), 1),
        log_stacking_height,
    )
}
