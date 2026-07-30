use itertools::Itertools;

use slop_algebra::{rlc_univariate_polynomials, ExtensionField, Field, UnivariatePolynomial};
use slop_challenger::{FieldChallenger, VariableLengthChallenger};

use crate::{ComponentPoly, PartialSumcheckProof, SumcheckPoly, SumcheckPolyFirstRound};

/// Proves a sumcheck for any sumcheckable polynomial, by reducing it to a claim about the
/// evaluation of the polynomial at a point.
///
///  # Panics
///  Will panic if the polynomial has zero variables.
pub fn reduce_sumcheck_to_evaluation<
    F: Field,
    EF: ExtensionField<F> + Send + Sync,
    Challenger: FieldChallenger<F>,
>(
    polys: Vec<impl SumcheckPolyFirstRound<EF, NextRoundPoly: Send + Sync> + Send + Sync>,
    challenger: &mut Challenger,
    claims: Vec<EF>,
    t: usize,
    lambda: EF,
) -> (PartialSumcheckProof<EF>, Vec<Vec<EF>>) {
    assert!(!polys.is_empty());
    // Check that all the polynomials have the same number of variables.

    let num_variables = polys[0].num_variables();

    // Check that all the polynomials have the same number of variables.
    assert!(polys.iter().all(|poly| poly.num_variables() == num_variables));

    // The first round will process the first t variables, so we need to ensure that there are at
    // least t variables.
    assert!(num_variables >= t as u32);

    // The point at which the reduced sumcheck proof should be evaluated.
    let mut point = vec![];

    // The univariate poly messages.  This will be a rlc of the polys' univariate polys.
    let mut univariate_poly_msgs: Vec<UnivariatePolynomial<EF>> = vec![];

    let mut uni_polys: Vec<_> = polys
        .iter()
        .zip(claims.iter())
        .map(|(poly, claim)| poly.sum_as_poly_in_last_t_variables(Some(*claim), t))
        .collect();

    let mut rlc_uni_poly = rlc_univariate_polynomials(&uni_polys, lambda);
    let coefficients =
        rlc_uni_poly.coefficients.iter().flat_map(|x| x.as_base_slice()).copied().collect_vec();
    challenger.observe_constant_length_slice(&coefficients);

    univariate_poly_msgs.push(rlc_uni_poly);

    let alpha: EF = challenger.sample_ext_element();
    point.insert(0, alpha);
    let mut polys_cursor: Vec<_> =
        polys.into_iter().map(|poly| poly.fix_t_variables(alpha, t)).collect();
    // The multi-variate polynomial used at the start of each sumcheck round.
    for _ in t..num_variables as usize {
        // Get the round claims from the last round's univariate poly messages.
        let round_claims = uni_polys.iter().map(|poly| poly.eval_at_point(*point.first().unwrap()));

        uni_polys = polys_cursor
            .iter()
            .zip_eq(round_claims)
            .map(|(poly, round_claim)| poly.sum_as_poly_in_last_variable(Some(round_claim)))
            .collect();
        rlc_uni_poly = rlc_univariate_polynomials(&uni_polys, lambda);
        challenger.observe_constant_length_extension_slice(&rlc_uni_poly.coefficients);

        univariate_poly_msgs.push(rlc_uni_poly);

        let alpha: EF = challenger.sample_ext_element();
        point.insert(0, alpha);
        polys_cursor = polys_cursor.into_iter().map(|poly| poly.fix_last_variable(alpha)).collect();
    }

    let evals =
        uni_polys.iter().map(|poly| poly.eval_at_point(*point.first().unwrap())).collect_vec();

    let component_poly_evals: Vec<_> =
        polys_cursor.iter().map(|poly| poly.get_component_poly_evals()).collect();

    (
        PartialSumcheckProof {
            univariate_polys: univariate_poly_msgs,
            claimed_sum: claims.into_iter().fold(EF::zero(), |acc, x| acc * lambda + x),
            point_and_eval: (
                point.into(),
                evals.into_iter().fold(EF::zero(), |acc, x| acc * lambda + x),
            ),
        },
        component_poly_evals,
    )
}
