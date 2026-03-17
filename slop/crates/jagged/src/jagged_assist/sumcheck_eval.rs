use serde::{Deserialize, Serialize};
use slop_algebra::{ExtensionField, Field};
use slop_alloc::{Buffer, CanCopyFrom, CpuBackend};
use slop_challenger::{FieldChallenger, FromChallenger, VariableLengthChallenger};
use slop_multilinear::{Mle, Point, PointBackend};
use slop_sumcheck::{partially_verify_sumcheck_proof, PartialSumcheckProof, SumcheckError};
use slop_tensor::Tensor;
use slop_utils::log2_ceil_usize;
use std::{fmt::Debug, marker::PhantomData};
use thiserror::Error;

use crate::{
    poly::BranchingProgram, JaggedLittlePolynomialProverParams,
    JaggedLittlePolynomialVerifierParams,
};

use super::{
    prove_jagged_eval_sumcheck, sumcheck_poly::JaggedEvalSumcheckPoly, JaggedAssistSumAsPoly,
    JaggedEvalProver,
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

        let (first_half_z_index, second_half_z_index) = partial_sumcheck_proof
            .point_and_eval
            .0
            .split_at(partial_sumcheck_proof.point_and_eval.0.dimension() / 2);

        if first_half_z_index.dimension() != second_half_z_index.dimension() {
            return Err(JaggedEvalSumcheckError::IncorrectShape);
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
                    let mut merged_prefix_sum = current_column_prefix_sum.clone();
                    merged_prefix_sum.extend(next_column_prefix_sum);

                    if current_column_prefix_sum.dimension() != next_column_prefix_sum.dimension() {
                        return Err(JaggedEvalSumcheckError::IncorrectShape);
                    }

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
        jagged_eval_sc_expected_eval *=
            branching_program.eval(&first_half_z_index, &second_half_z_index);

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct JaggedEvalSumcheckProver<F, BPE, A, DeviceChallenger>(
    pub PhantomData<(F, BPE, A, DeviceChallenger)>,
);

impl<F, BPE, A, DC> Default for JaggedEvalSumcheckProver<F, BPE, A, DC> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<F, EF, Challenger, BPE, A, DeviceChallenger> JaggedEvalProver<F, EF, Challenger>
    for JaggedEvalSumcheckProver<F, BPE, A, DeviceChallenger>
where
    JaggedEvalSumcheckProver<F, BPE, A, DeviceChallenger>: 'static,
    F: Field,
    EF: ExtensionField<F>,
    Challenger: FieldChallenger<F> + Send + Sync,
    DeviceChallenger: FromChallenger<Challenger, A> + Clone + Send + Sync,
    BPE: JaggedAssistSumAsPoly<F, EF, A, Challenger, DeviceChallenger> + Send + Sync + Clone,
    A: PointBackend<EF>
        + PointBackend<F>
        + CanCopyFrom<Buffer<EF>, CpuBackend, Output = Buffer<EF, A>>
        + CanCopyFrom<Buffer<F>, CpuBackend, Output = Buffer<F, A>>,
{
    type A = A;

    fn prove_jagged_evaluation(
        &self,
        params: &JaggedLittlePolynomialProverParams,
        z_row: &Point<EF>,
        z_col: &Point<EF>,
        z_trace: &Point<EF>,
        challenger: &mut Challenger,
        backend: Self::A,
    ) -> JaggedSumcheckEvalProof<EF> {
        // Create sumcheck proof for the jagged eval.
        let jagged_eval_sc_poly = JaggedEvalSumcheckPoly::<
            F,
            EF,
            Challenger,
            DeviceChallenger,
            BPE,
            A,
        >::new_from_jagged_params(
            z_row.clone(),
            z_col.clone(),
            z_trace.clone(),
            params.col_prefix_sums_usize.clone(),
            backend.clone(),
        );

        // Compute the full eval of the jagged poly.
        let verifier_params = params.clone().into_verifier_params();
        let expected_sum =
            verifier_params.full_jagged_little_polynomial_evaluation(z_row, z_col, z_trace);

        let log_m = log2_ceil_usize(*params.col_prefix_sums_usize.last().unwrap());

        let mut sum_values = Tensor::zeros_in([3, 2 * (log_m + 1)], backend.clone()).into_buffer();

        challenger.observe_ext_element(expected_sum);

        let mut device_challenger =
            <DeviceChallenger as FromChallenger<Challenger, A>>::from_challenger(
                challenger, &backend,
            );

        let partial_sumcheck_proof = prove_jagged_eval_sumcheck(
            jagged_eval_sc_poly,
            &mut device_challenger,
            expected_sum,
            1,
            &mut sum_values,
        );

        // The CPU challenger needs to observe the polynomial coefficients to sync with the state
        // of the device challenger. This could also be done by copying the device challenger
        // state to CPU.
        for poly in &partial_sumcheck_proof.univariate_polys {
            challenger.observe_constant_length_extension_slice(&poly.coefficients);
            let _: EF = challenger.sample_ext_element();
        }

        JaggedSumcheckEvalProof { partial_sumcheck_proof }
    }
}
