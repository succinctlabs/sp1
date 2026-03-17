use slop_algebra::{interpolate_univariate_polynomial, ExtensionField, Field};
use slop_alloc::{Backend, Buffer};
use slop_challenger::FieldChallenger;
use slop_sumcheck::PartialSumcheckProof;

use super::{JaggedAssistSumAsPoly, JaggedEvalSumcheckPoly};

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
    DeviceChallenger,
    BPE: JaggedAssistSumAsPoly<F, EF, A, Challenger, DeviceChallenger> + Send + Sync,
    A: Backend,
>(
    mut poly: JaggedEvalSumcheckPoly<F, EF, Challenger, DeviceChallenger, BPE, A>,
    challenger: &mut DeviceChallenger,
    claim: EF,
    t: usize,
    sum_values: &mut Buffer<EF, A>,
) -> PartialSumcheckProof<EF> {
    let num_variables = poly.num_variables();

    // The first round of sumcheck.
    let mut round_claim = poly.sum_as_poly_in_last_t_variables_observe_and_sample(
        Some(claim),
        sum_values,
        challenger,
        t,
    );

    let mut polys_cursor = BPE::fix_last_variable(poly);

    for _ in t..num_variables as usize {
        round_claim = polys_cursor.sum_as_poly_in_last_variable_observe_and_sample(
            Some(round_claim),
            sum_values,
            challenger,
        );

        polys_cursor = BPE::fix_last_variable(polys_cursor);
    }

    // Move the `sum_as_poly` evaluations to the CPU.
    let host_sum_values = unsafe { sum_values.copy_into_host_vec() };

    let univariate_polys = host_sum_values
        .as_slice()
        // The jagged eval sumcheck is of degree 2, which means that there are 3 evaluations needed
        // per round of sumcheck.
        .chunks_exact(3)
        .map(|chunk| {
            // Compute the univariate polynomial message.
            let ys: [EF; 3] = chunk.try_into().unwrap();
            let xs: [EF; 3] = [EF::zero(), EF::two().inverse(), EF::one()];
            interpolate_univariate_polynomial(&xs, &ys)
        })
        .collect::<Vec<_>>();

    // Move the randomness point to the CPU.
    let point_host = unsafe { polys_cursor.rho.values().copy_into_host_vec() };

    let final_claim: EF =
        univariate_polys.last().unwrap().eval_at_point(point_host.first().copied().unwrap());

    PartialSumcheckProof {
        univariate_polys,
        claimed_sum: claim,
        point_and_eval: (point_host.into(), final_claim),
    }
}
