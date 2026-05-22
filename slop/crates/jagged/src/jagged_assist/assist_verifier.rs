use serde::{Deserialize, Serialize};
use slop_algebra::{ExtensionField, Field};
use slop_challenger::FieldChallenger;
use slop_multilinear::{Mle, Point};
use slop_sumcheck::{partially_verify_sumcheck_proof, PartialSumcheckProof, SumcheckError};
use std::{fmt::Debug, marker::PhantomData};
use thiserror::Error;

use crate::{
    deinterleave_prefix_sums, interleave_prefix_sums, poly::BranchingProgram,
    JaggedLittlePolynomialVerifierParams,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JaggedSumcheckEvalProof<F> {
    pub partial_sumcheck_proof: PartialSumcheckProof<F>,
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
}

impl<F> JaggedEvalSumcheckConfig<F>
where
    F: Field,
{
    pub fn jagged_evaluation<EF: ExtensionField<F>, Challenger: FieldChallenger<F>>(
        params: &JaggedLittlePolynomialVerifierParams<F>,
        z_row: &Point<EF>,
        z_col: &Point<EF>,
        z_trace: &Point<EF>,
        proof: &JaggedSumcheckEvalProof<EF>,
        challenger: &mut Challenger,
    ) -> Result<EF, JaggedEvalSumcheckError<EF>> {
        let JaggedSumcheckEvalProof { partial_sumcheck_proof } = proof;
        // Calculate the partial lagrange from z_col point.
        let z_col_partial_lagrange = Mle::blocking_partial_lagrange(z_col);
        let z_col_partial_lagrange = z_col_partial_lagrange.guts().as_slice();

        let jagged_eval = partial_sumcheck_proof.claimed_sum;

        challenger.observe_ext_element(jagged_eval);

        // Check the evaluation is the claimed sum of the sumcheck.
        if jagged_eval != partial_sumcheck_proof.claimed_sum {
            return Err(JaggedEvalSumcheckError::IncorrectEvaluation);
        }

        // Check that the `col_prefix_sums` is non-empty.
        if params.col_prefix_sums.is_empty() {
            return Err(JaggedEvalSumcheckError::IncorrectShape);
        }

        // Verify the jagged eval proof.
        let result = partially_verify_sumcheck_proof(
            partial_sumcheck_proof,
            challenger,
            2 * params.col_prefix_sums[0].dimension(),
            2,
        );

        if let Err(result) = result {
            return Err(JaggedEvalSumcheckError::SumcheckError(result));
        }

        if params.col_prefix_sums.len() - 1 > z_col_partial_lagrange.len() {
            return Err(JaggedEvalSumcheckError::IncorrectShape);
        }

        // Compute the jagged eval sc expected eval and assert it matches the proof's eval.
        let current_column_prefix_sums = params.col_prefix_sums.iter();
        let next_column_prefix_sums = params.col_prefix_sums.iter().skip(1);
        let mut is_first_column = true;
        let mut prev_merged_prefix_sum = Point::<F>::default();
        let mut prev_full_lagrange_eval = EF::zero();
        let mut jagged_eval_sc_expected_eval = current_column_prefix_sums
            .zip(next_column_prefix_sums)
            .zip(z_col_partial_lagrange.iter())
            .try_fold(
                EF::zero(),
                |acc, ((current_column_prefix_sum, next_column_prefix_sum), z_col_eq_val)| {
                    if current_column_prefix_sum.dimension() != next_column_prefix_sum.dimension() {
                        return Err(JaggedEvalSumcheckError::IncorrectShape);
                    }

                    // The assert in this function call is never triggered, since the two points are checked
                    // above to have the same dimension.
                    let merged_prefix_sum =
                        interleave_prefix_sums(current_column_prefix_sum, next_column_prefix_sum);

                    if merged_prefix_sum.dimension()
                        != partial_sumcheck_proof.point_and_eval.0.dimension()
                    {
                        return Err(JaggedEvalSumcheckError::IncorrectShape);
                    }

                    let full_lagrange_eval =
                        if prev_merged_prefix_sum == merged_prefix_sum && !is_first_column {
                            prev_full_lagrange_eval
                        } else {
                            let full_lagrange_eval = Mle::full_lagrange_eval(
                                &merged_prefix_sum,
                                &partial_sumcheck_proof.point_and_eval.0,
                            );
                            prev_full_lagrange_eval = full_lagrange_eval;
                            full_lagrange_eval
                        };

                    prev_merged_prefix_sum = merged_prefix_sum;
                    is_first_column = false;

                    Ok(acc + *z_col_eq_val * full_lagrange_eval)
                },
            )?;

        let branching_program = BranchingProgram::new(z_row.clone(), z_trace.clone());

        // The assert that occurs in `deinterleav_prefix_sums` is guaranteed not to trigger because
        // the shape check has already checked that the dimension of this point is equal to `merged_prefix_sum.dimension()`
        // which is constructed as the interleaving of two points of the same dimension.
        let (curr, next) = deinterleave_prefix_sums(&partial_sumcheck_proof.point_and_eval.0);
        jagged_eval_sc_expected_eval *= branching_program.eval(&curr, &next);

        if jagged_eval_sc_expected_eval != partial_sumcheck_proof.point_and_eval.1 {
            Err(JaggedEvalSumcheckError::JaggedEvaluationFailed(
                jagged_eval_sc_expected_eval,
                partial_sumcheck_proof.point_and_eval.1,
            ))
        } else {
            Ok(jagged_eval)
        }
    }
}
