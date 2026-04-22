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

/// Opaque handle the verifier hands out for each committed oracle. The digest and
/// shape live in [`TransparentVerifierCtx::oracle_commits`]; this is just an index.
#[derive(Clone, Copy, Debug)]
pub struct TransparentVerifierOracle {
    /// Index into `TransparentVerifierCtx::oracle_commits`.
    idx: usize,
}

/// One asserted polynomial constraint: an expression that must evaluate to zero.
struct ZeroClaim<EF> {
    expr: Expr<EF>,
    name: String,
}

/// One pending MLE-eval claim group: all oracles are opened at the same point.
/// Paired with one [`StackedBasefoldProof`] from the prover.
struct MleClaimGroup<EF> {
    oracles: Vec<TransparentVerifierOracle>,
    eval_exprs: Vec<Expr<EF>>,
    point: Point<EF>,
    name: String,
}

/// Which constraint list was appended to most recently. Used by
/// [`ConstraintCtx::name_last_constraint`] to know where to write the override.
#[derive(Clone, Copy, Debug)]
enum LastConstraintKind {
    Zero,
    Mle,
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("constraint(s) failed: {}", .0.join(", "))]
    ConstraintsFailed(Vec<String>),
    #[error("number of PCS proofs ({expected}) does not match number of MLE eval claim groups ({actual})")]
    PcsProofCountMismatch { expected: usize, actual: usize },
    #[error("MLE claim group {group_idx}: proof has {actual} per-oracle batch_evaluations but group has {expected} oracles")]
    GroupOracleCountMismatch { group_idx: usize, expected: usize, actual: usize },
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
    /// One entry per committed oracle: `(digest, num_encoding_variables, log_num_polynomials)`.
    /// Shapes come from the proof; `read_oracle` checks them against the caller's
    /// requested shape.
    oracle_commits: Vec<(GC::Digest, u32, u32)>,
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
    zero_claims: Vec<ZeroClaim<GC::EF>>,
    mle_claims: Vec<MleClaimGroup<GC::EF>>,
    /// Tracks which constraint list received the most recent push, so
    /// `name_last_constraint` knows where to write its override.
    last_constraint_kind: Option<LastConstraintKind>,

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
            mle_claims: Vec::new(),
            last_constraint_kind: None,
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

    /// Advance the cursor, push a `Var` node for that transcript slot, and return
    /// both the fresh pool handle and the slot it reads from.
    fn push_var(&mut self) -> (Element<GC::EF>, (usize, usize)) {
        let (g, l) = self.advance_read_cursor();
        let idx = self.pool.borrow_mut().push(ExprNode::Var(g, l));
        (Element::new(self.pool.clone(), idx), (g, l))
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
            let (elem, (g, l)) = self.push_var();
            *slot = Expr::Node(elem);
            self.challenger.observe_ext_element(self.transcript[g][l]);
        }
        Ok(())
    }

    fn read_oracle(
        &mut self,
        num_encoding_variables: u32,
        log_num_polynomials: u32,
    ) -> Option<Self::MleOracle> {
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

impl<GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>> TransparentVerifierCtx<GC> {
    /// Run the full verification pass:
    ///
    /// 1. Evaluate every node in the expression pool (single linear sweep).
    /// 2. Check every `assert_zero` claim evaluates to zero. (`a*b=c` claims are
    ///    lowered to `assert_zero(a*b - c)` via the trait default, so there's no
    ///    separate list for them.)
    /// 3. For each recorded MLE-eval claim group, dispatch to the stacked-basefold
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

        // 3. MLE-eval claim groups → PCS checks.
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

            for (group_idx, (group, pcs_proof)) in
                self.mle_claims.iter().zip(&self.pcs_proofs).enumerate()
            {
                // Assemble the inputs that `verify_trusted_evaluation` expects.
                let commits: Vec<GC::Digest> =
                    group.oracles.iter().map(|o| self.oracle_commits[o.idx].0).collect();
                let round_areas: Vec<usize> = group
                    .oracles
                    .iter()
                    .map(|o| {
                        let (_, num_enc, log_num) = self.oracle_commits[o.idx];
                        (1usize << (num_enc + log_num))
                            .next_multiple_of(1usize << pcs_verifier.log_stacking_height)
                    })
                    .collect();

                // Per-oracle cross-check of user claim vs. proof-recovered eval:
                // the proof's `batch_evaluations[i]` carries oracle `i`'s stacked
                // column-evaluations at the stack_point prefix of `eval_point`.
                // Folding them at `batch_point` (the remaining coordinates of
                // `eval_point`) recovers oracle `i`'s evaluation at the full point.
                // We tie that to the protocol's claim by comparing against the
                // user's `eval_expr[i]` evaluated through the expression pool.
                //
                // The stacked PCS's own `verify_trusted_evaluation` only checks
                // this binding for the first oracle (via `[0]` on a flattened MLE)
                // — so for multi-oracle groups this per-oracle loop is what closes
                // the soundness loop. The trailing PCS call below then runs the
                // FRI + Merkle + stacking layers to confirm `batch_evaluations`
                // really came from the committed MLEs.
                if pcs_proof.batch_evaluations.len() != group.oracles.len() {
                    return Err(VerifyError::GroupOracleCountMismatch {
                        group_idx,
                        expected: group.oracles.len(),
                        actual: pcs_proof.batch_evaluations.len(),
                    });
                }
                let eval_point = group.point.clone();
                let log_stack = pcs_verifier.log_stacking_height as usize;
                let (batch_point, _) = eval_point.split_at(eval_point.dimension() - log_stack);
                for (oracle_idx, eval_expr) in group.eval_exprs.iter().enumerate() {
                    let per_oracle_mle: Mle<GC::EF> =
                        pcs_proof.batch_evaluations[oracle_idx].to_vec().into();
                    let proof_eval = per_oracle_mle.blocking_eval_at(&batch_point)[0];
                    let user_eval = evaluate_expr(eval_expr, &values);
                    if proof_eval != user_eval {
                        return Err(VerifyError::EvalClaimMismatch { group_idx, oracle_idx });
                    }
                }

                // Flattened eval_claim for the stacked PCS layer. This is the form
                // `verify_trusted_evaluation` expects; it's self-consistent with the
                // proof's `batch_evaluations`, but the per-oracle loop above has
                // already bound user claims to those `batch_evaluations`.
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
