use slop_algebra::{interpolate_univariate_polynomial, ExtensionField, Field};
use slop_alloc::Buffer;
use slop_challenger::FieldChallenger;
use slop_sumcheck::PartialSumcheckProof;

use super::JaggedEvalSumcheckPoly;

/// The standard implementation of the sumcheck prover from an implementation of `SumcheckPoly`
/// makes assumptions about how the Fiat-Shamir challenges are observed and sampled. This function
/// produces a sumcheck proof using slightly different assumptions on the polynomial and the
/// challenger, and in particular allows for the possibility of keeping intermediate results on
/// hardware memory and copying them to the CPU only at the end.
///
///  # Panics
///  Will panic if the polynomial has zero variables.
pub fn prove_jagged_eval_sumcheck<
    F: Field,
    EF: ExtensionField<F> + Send + Sync,
    Challenger: FieldChallenger<F> + Send + Sync,
>(
    mut poly: JaggedEvalSumcheckPoly<F, EF, Challenger>,
    challenger: &mut Challenger,
    claim: EF,
    t: usize,
    sum_values: &mut Buffer<EF>,
) -> PartialSumcheckProof<EF> {
    let num_variables = poly.num_variables();

    // The first round of sumcheck.
    let mut round_claim = poly.sum_as_poly_in_last_t_variables_observe_and_sample(
        Some(claim),
        sum_values,
        challenger,
        t,
    );

    poly.fix_last_variable();

    for _ in t..num_variables as usize {
        round_claim = poly.sum_as_poly_in_last_variable_observe_and_sample(
            Some(round_claim),
            sum_values,
            challenger,
        );

        poly.fix_last_variable();
    }

    let univariate_polys = sum_values
        .as_slice()
        .chunks_exact(3)
        .map(|chunk| {
            // Compute the univariate polynomial message.
            let ys: [EF; 3] = chunk.try_into().unwrap();
            let xs: [EF; 3] = [EF::zero(), EF::two().inverse(), EF::one()];
            interpolate_univariate_polynomial(&xs, &ys)
        })
        .collect::<Vec<_>>();

    let rho_vec = poly.rho.to_vec();

    let final_claim: EF = univariate_polys.last().unwrap().eval_at_point(*rho_vec.first().unwrap());

    PartialSumcheckProof {
        univariate_polys,
        claimed_sum: claim,
        point_and_eval: (rho_vec.into(), final_claim),
    }
}
