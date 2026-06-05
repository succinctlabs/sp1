use thiserror::Error;

use slop_algebra::{ExtensionField, Field};
use slop_challenger::{FieldChallenger, VariableLengthChallenger};
use slop_multilinear::Point;

use crate::PartialSumcheckProof;

#[derive(Debug, Eq, PartialEq, Error)]
pub enum SumcheckError {
    #[error("invalid proof shape")]
    InvalidProofShape,
    #[error("sumcheck round inconsistency")]
    SumcheckRoundInconsistency(usize),
    #[error("inconsistency of prover message with claimed sum")]
    InconsistencyWithClaimedSum,
    #[error("inconsistency of proof with evaluation claim")]
    InconsistencyWithEval,
}

/// Verifies that a PartialSumcheckProof is correct up until the evaluation claim.
pub fn partially_verify_sumcheck_proof<
    F: Field,
    EF: ExtensionField<F>,
    Challenger: FieldChallenger<F>,
>(
    proof: &PartialSumcheckProof<EF>,
    challenger: &mut Challenger,
    expected_num_variable: usize,
    expected_degree: usize,
) -> Result<(), SumcheckError> {
    let num_variables = proof.univariate_polys.len();
    let mut alpha_point = Point::default();

    // Checks for the correct proof shape.
    if num_variables != proof.point_and_eval.0.dimension() {
        return Err(SumcheckError::InvalidProofShape);
    }

    if num_variables != expected_num_variable {
        return Err(SumcheckError::InvalidProofShape);
    }

    if expected_num_variable == 0 {
        return Err(SumcheckError::InvalidProofShape);
    }

    // There is a way to structure a sumcheck proof so that this check is not needed, but it doesn't
    // actually save the verifier work.
    let first_poly = &proof.univariate_polys[0];
    if first_poly.eval_one_plus_eval_zero() != proof.claimed_sum {
        return Err(SumcheckError::InconsistencyWithClaimedSum);
    }

    if first_poly.coefficients.len() != expected_degree + 1 {
        return Err(SumcheckError::InvalidProofShape);
    }

    // The degree of this polynomial is checked against `expected_degree`, which is considered to be
    // agreed upon between the prover and verifier before the proof starts, which is why we don't
    // observe it here.
    challenger.observe_constant_length_extension_slice(&first_poly.coefficients);
    let mut previous_poly = first_poly;

    for (i, poly) in proof.univariate_polys.iter().skip(1).enumerate() {
        if poly.coefficients.len() != expected_degree + 1 {
            return Err(SumcheckError::InvalidProofShape);
        }
        let alpha = challenger.sample_ext_element();
        alpha_point.add_dimension(alpha);
        let expected_eval = previous_poly.eval_at_point(alpha);
        if expected_eval != poly.eval_one_plus_eval_zero() {
            return Err(SumcheckError::SumcheckRoundInconsistency(i + 1));
        }
        challenger.observe_constant_length_extension_slice(&poly.coefficients);
        previous_poly = poly;
    }

    let alpha = challenger.sample_ext_element();
    alpha_point.add_dimension(alpha);

    // Check that the randomness generated for the prover is the same as the one obtained by the
    // verifier. There is a way to structure a sumcheck proof so that this check is not needed,
    // but it doesn't actually save the verifier work.
    if alpha_point != proof.point_and_eval.0 {
        return Err(SumcheckError::InvalidProofShape);
    }

    // Check that the evaluation claim implied by the last univariate polynomial matches the
    // evaluation claim in the proof struct.
    // There is a way to structure a sumcheck proof so that this check is not needed, but it doesn't
    // actually save the verifier work.
    if previous_poly.eval_at_point(alpha) != proof.point_and_eval.1 {
        return Err(SumcheckError::InconsistencyWithEval);
    }

    Ok(())
}
