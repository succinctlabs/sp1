use slop_algebra::{Field, TwoAdicField};
use slop_basefold::BasefoldVerifier;
use slop_challenger::{CanObserve, FieldChallenger, IopCtx};
use slop_multilinear::{Mle, Point};
use slop_stacked::{StackedBasefoldProof, StackedPcsVerifier, StackedVerifierError};
use thiserror::Error;

use crate::compiler::{AssertZeroError, ConstraintCtx, ReadingCtx, TranscriptReadError};
use crate::transparent::prover::TransparentProof;

/// Opaque handle the verifier hands out for each committed oracle. The digest and
/// shape live in [`TransparentVerifierCtx::oracle_commits`]; this is just an index.
#[derive(Clone, Copy, Debug)]
pub struct TransparentVerifierOracle {
    /// Index into `TransparentVerifierCtx::oracle_commits`.
    idx: usize,
}

/// One pending MLE-eval claim group: all oracles are opened at the same point.
/// Paired with one [`StackedBasefoldProof`] from the prover.
struct MleClaimGroup<EF> {
    oracles: Vec<TransparentVerifierOracle>,
    /// User-claimed evaluation for each oracle at `point`. Cross-checked against
    /// the proof's `batch_evaluations` at `verify()` time.
    evals: Vec<EF>,
    point: Point<EF>,
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("number of PCS proofs ({expected}) does not match number of MLE eval claim groups ({actual})")]
    PcsProofCountMismatch { expected: usize, actual: usize },
    #[error("MLE claim group {group_idx}: proof has {actual} per-oracle batch_evaluations but group has {expected} oracles")]
    GroupOracleCountMismatch { group_idx: usize, expected: usize, actual: usize },
    #[error("MLE claim group {group_idx}, oracle {oracle_idx}: user-claimed eval does not match the proof's recovered eval")]
    EvalClaimMismatch { group_idx: usize, oracle_idx: usize },
    #[error(transparent)]
    PcsError(
        StackedVerifierError<
            slop_basefold::BaseFoldVerifierError<slop_merkle_tree::MerkleTreeTcsError>,
        >,
    ),
}

/// Transparent verifier context.
///
/// There is no masking and no compiled constraint language in the transparent
/// backend — `Expr` is just the underlying extension-field element. Every
/// `assert_zero` / `assert_a_times_b_equals_c` call eagerly evaluates its
/// argument and returns [`AssertZeroError`] on a non-zero value; MLE-eval
/// claims are queued (together with their concrete claimed values) and
/// discharged against the stacked-basefold PCS proofs at [`Self::verify`] time.
pub struct TransparentVerifierCtx<GC: IopCtx> {
    // From the proof.
    transcript: Vec<Vec<GC::EF>>,
    /// One entry per committed oracle: `(digest, num_encoding_variables, log_num_polynomials)`.
    /// Shapes come from the proof; `read_oracle` checks them against the caller's
    /// requested shape.
    oracle_commits: Vec<(GC::Digest, u32, u32)>,
    pcs_proofs: Vec<StackedBasefoldProof<GC>>,

    // Traversal cursors.
    /// Next transcript message to read.
    read_cursor: usize,
    /// Next commitment to hand out as an oracle.
    oracle_cursor: usize,

    // Fiat-Shamir.
    challenger: GC::Challenger,

    // Pending PCS claim groups.
    mle_claims: Vec<MleClaimGroup<GC::EF>>,

    // PCS verifier (`None` if the protocol emitted no MLE claims).
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
            read_cursor: 0,
            oracle_cursor: 0,
            challenger: GC::default_challenger(),
            mle_claims: Vec::new(),
            pcs_verifier,
        }
    }

    // /// Advance the read cursor by one and return the position that was read.
    // /// If the read cursor has overrun the transcript, do not advance.
    // /// The error will be caught by read_exact
    // fn advance_read_cursor(&mut self) -> (usize, usize) {
    //     let (g, l) = self.read_cursor;
    //     if l < self.transcript[g].len() {
    //         self.read_cursor.1 += 1;
    //         return (g, l);
    //     }
    //     if g < self.transcript.len() - 1 {
    //         self.read_cursor.0 += 1;
    //         self.read_cursor.1 = 0;
    //         return self.read_cursor;
    //     }
    //     self.read_cursor
    // }
}

// ============================================================================
// ConstraintCtx
// ============================================================================

impl<GC: IopCtx> ConstraintCtx for TransparentVerifierCtx<GC> {
    type Field = GC::F;
    type Extension = GC::EF;
    type Expr = GC::EF;
    type Challenge = GC::EF;
    type MleOracle = TransparentVerifierOracle;
    type AssertError = AssertZeroError<GC::EF>;

    fn assert_zero(&mut self, expr: Self::Expr) -> Result<(), Self::AssertError> {
        if expr.is_zero() {
            Ok(())
        } else {
            Err(AssertZeroError(expr))
        }
    }

    fn assert_mle_multi_eval(
        &mut self,
        claims: Vec<(Self::MleOracle, Self::Expr)>,
        point: Point<Self::Challenge>,
    ) {
        let mut oracles = Vec::with_capacity(claims.len());
        let mut evals = Vec::with_capacity(claims.len());
        for (oracle, eval) in claims {
            oracles.push(oracle);
            evals.push(eval);
        }
        self.mle_claims.push(MleClaimGroup { oracles, evals, point });
    }
}

// ============================================================================
// ReadingCtx
// ============================================================================

impl<GC: IopCtx> ReadingCtx for TransparentVerifierCtx<GC> {
    fn read_exact(&mut self, buf: &mut [Self::Expr]) -> Result<(), TranscriptReadError> {
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
    /// Discharge all pending MLE-eval claim groups against the stacked-basefold
    /// PCS proofs. Polynomial `assert_zero` / `a*b=c` constraints are already
    /// checked eagerly at call time (returning [`AssertZeroError`]), so by the
    /// time this runs, all remaining work is PCS verification.
    ///
    /// For each claim group: cross-check each user-claimed eval against the
    /// proof's per-oracle `batch_evaluations`, then dispatch to the stacked-
    /// basefold PCS verifier using the matching `pcs_proofs[i]`.
    pub fn verify(mut self) -> Result<(), VerifyError> {
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
                let commits: Vec<GC::Digest> =
                    group.oracles.iter().map(|o| self.oracle_commits[o.idx].0).collect();
                let round_areas: Vec<usize> = group
                    .oracles
                    .iter()
                    .map(|o| {
                        let (_, num_enc, log_num_poly) = self.oracle_commits[o.idx];
                        (1usize << (num_enc + log_num_poly))
                            .next_multiple_of(1usize << pcs_verifier.log_stacking_height)
                    })
                    .collect();

                let eval_point = group.point.clone();
                let log_stack = pcs_verifier.log_stacking_height as usize;
                let (batch_point, _) = eval_point.split_at(eval_point.dimension() - log_stack);

                // Per-oracle cross-check: user's claim vs. proof-recovered eval.
                // Since `Expr = EF` in this backend, the user's claim is already a
                // concrete field element — just compare directly.
                if pcs_proof.batch_evaluations.len() != group.oracles.len() {
                    return Err(VerifyError::GroupOracleCountMismatch {
                        group_idx,
                        expected: group.oracles.len(),
                        actual: pcs_proof.batch_evaluations.len(),
                    });
                }
                for (oracle_idx, user_eval) in group.evals.iter().enumerate() {
                    let per_oracle_mle: Mle<GC::EF> =
                        pcs_proof.batch_evaluations[oracle_idx].to_vec().into();
                    let proof_eval = per_oracle_mle.blocking_eval_at(&batch_point)[0];
                    if proof_eval != *user_eval {
                        return Err(VerifyError::EvalClaimMismatch { group_idx, oracle_idx });
                    }
                }

                // Flattened eval_claim for the stacked PCS layer. Self-consistent
                // with the proof's `batch_evaluations`; the per-oracle loop above
                // already binds user claims to those `batch_evaluations`.
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
