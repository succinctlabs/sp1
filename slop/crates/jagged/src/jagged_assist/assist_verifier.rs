use serde::{Deserialize, Serialize};
use slop_algebra::{ExtensionField, Field};
use slop_challenger::FieldChallenger;
use slop_multilinear::{full_geq, Point};
use slop_sumcheck::{partially_verify_sumcheck_proof, PartialSumcheckProof, SumcheckError};
use std::{fmt::Debug, marker::PhantomData};
use thiserror::Error;

use crate::{
    deinterleave_prefix_sums,
    jagged_assist::{
        geq::sum_z_first_n_via_geq,
        two_stage_jagged::{lagrange_eval_at_zero_merged, zeta_padded, K1, K2},
    },
    poly::BranchingProgram,
    two_stage_eq_product_verifier::{
        verify_two_stage_eq_product, TwoStageEqError, TwoStageEqProductProof,
    },
    JaggedLittlePolynomialVerifierParams,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JaggedSumcheckEvalProof<F> {
    pub partial_sumcheck_proof: PartialSumcheckProof<F>,
    /// Two-stage-GKR proof that replaces the verifier's per-column
    /// `full_lagrange_eval` loop. To check the claimed sum of the previous sumcheck proof,
    /// the verifier would have to do the sum `sum_{i in cols} eq(z, i)eq(z', x[i])`, where
    /// the `x[i]` are a vector of `NUM_BITS*2` bits. The two-stage proof delegates this computation
    /// to the prover via a two-layer, high-fan-in GKR proof.
    pub two_stage_proof: TwoStageEqProductProof<F>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct JaggedEvalSumcheckConfig<F>(PhantomData<F>);

#[derive(Debug, Error)]
pub enum JaggedEvalSumcheckError<F: Field> {
    #[error("sumcheck error: {0}")]
    SumcheckError(SumcheckError),
    #[error("jagged evaluation proof verification failed, expected: {0}, got: {1}")]
    JaggedEvaluationFailed(F, F),
    #[error("proof has incorrect shape")]
    IncorrectShape,
    #[error("jagged evaluation does not match the claimed sumcheck sum")]
    IncorrectEvaluation,
    #[error("jagged 'remainder' two-stage proof verification failed")]
    TwoStageProofVerificationFailed(#[from] TwoStageEqError<F>),
}

impl<F> JaggedEvalSumcheckConfig<F>
where
    F: Field,
{
    /// Verifies the jagged evaluation proof against the given parameters.
    ///
    /// Returns: the evaluation of the "full" jagged polynomial at the given point, the new random
    /// point at which which the current/next prefix sum Mles are evaluated, and the claimed values
    /// of the prefix sum Mles.
    pub fn jagged_evaluation<EF: ExtensionField<F>, Challenger: FieldChallenger<F>>(
        params: &JaggedLittlePolynomialVerifierParams<F>,
        z_row: &Point<EF>,
        z_col: &Point<EF>,
        z_trace: &Point<EF>,
        proof: &JaggedSumcheckEvalProof<EF>,
        challenger: &mut Challenger,
    ) -> Result<(EF, Point<EF>, Vec<EF>), JaggedEvalSumcheckError<EF>> {
        let JaggedSumcheckEvalProof { partial_sumcheck_proof, two_stage_proof } = proof;

        // Check that the `col_prefix_sums` is non-empty.
        if params.col_prefix_sums.is_empty() {
            return Err(JaggedEvalSumcheckError::IncorrectShape);
        }

        // Sample alpha (combines the assist and geq claims), then observe the
        // fused claimed_sum — mirrors the prover's order so both FS states agree.
        let alpha: EF = challenger.sample_ext_element();
        let fused_claim = partial_sumcheck_proof.claimed_sum;
        challenger.observe_ext_element(fused_claim);

        // Verify the inner (assist + α · geq) sumcheck.
        let result = partially_verify_sumcheck_proof(
            partial_sumcheck_proof,
            challenger,
            2 * params.col_prefix_sums[0].dimension(),
            2,
        );

        if let Err(result) = result {
            return Err(JaggedEvalSumcheckError::SumcheckError(result));
        }

        // Recover the assist part from the fused claim.
        let num_real_pairs = params.col_prefix_sums.len() - 1;
        let sum_z_first_n: EF = sum_z_first_n_via_geq::<F, EF>(num_real_pairs, z_col);
        let jagged_eval = fused_claim - alpha * sum_z_first_n;

        // The inner sumcheck's claim about `Σ_col z_col_eq[col] · L(merged[col], ζ_sumcheck) · BP.eval`
        // lives in `partial_sumcheck_proof.point_and_eval.1`. We split it as
        //
        //   point_and_eval.1 = real_sum · BP.eval(curr, next),
        //
        // and replace the old per-col loop that computed `real_sum` directly
        // with a two-stage-GKR verification: prover claims `full_hypercube_sum
        // = real_sum + L(0, ζ_sumcheck) · (1 − sum_z_first_n)`, we verify the
        // two-stage transcripts + K final bit-MLE evals, then recover
        // `real_sum` by subtracting the closed-form padded term.
        let zeta_sumcheck: Vec<EF> =
            partial_sumcheck_proof.point_and_eval.0.iter().copied().collect();
        let log_num_cols = z_col.dimension();

        // ----- Two-stage GKR verification. -----
        // Verifies both transcripts, the stage-1→stage-2 claim transition, and the stage-2
        // eval claim re-derivation from the K announced p_k(η)'s, returning the verified
        // `stage1.claimed_sum`, as well as the η and the announced p_k(η)'s on success.
        let z_padded = zeta_padded(&zeta_sumcheck);

        let (stage1_claimed_sum, eta, final_evals) = verify_two_stage_eq_product::<F, EF, _>(
            two_stage_proof,
            z_col,
            &z_padded,
            K1,
            K2,
            log_num_cols,
            challenger,
        )?;

        // Recover `real_sum` by subtracting the closed-form padded contribution.
        let l_zero = lagrange_eval_at_zero_merged(&zeta_sumcheck);
        let padded_contribution = l_zero * (EF::one() - sum_z_first_n);
        let real_sum = stage1_claimed_sum - padded_contribution;

        let assist_bp = BranchingProgram::new(z_row.clone(), z_trace.clone());

        // The assert that occurs in `deinterleav_prefix_sums` is guaranteed not to trigger because
        // the shape check has already checked that the dimension of this point is equal to `merged_prefix_sum.dimension()`
        // which is constructed as the interleaving of two points of the same dimension.
        let (curr, next) = deinterleave_prefix_sums(&partial_sumcheck_proof.point_and_eval.0);
        let assist_eval = assist_bp.eval(&curr, &next);
        let mut jagged_eval_sc_expected_eval = real_sum;
        let geq_eval = full_geq(&curr, &next);
        jagged_eval_sc_expected_eval *= assist_eval + alpha * geq_eval;

        if jagged_eval_sc_expected_eval != partial_sumcheck_proof.point_and_eval.1 {
            Err(JaggedEvalSumcheckError::JaggedEvaluationFailed(
                jagged_eval_sc_expected_eval,
                partial_sumcheck_proof.point_and_eval.1,
            ))
        } else {
            Ok((jagged_eval, eta, final_evals))
        }
    }
}
