use crate::zk::inner::{ZkIopCtx, ZkMerkleizer};
use crate::zk::stacked_pcs::prover::{StackedPcsProverValue, StackedPcsZkProverContext};
use derive_where::derive_where;
use itertools::Itertools;
use slop_algebra::{rlc_univariate_polynomials, AbstractField};
use slop_challenger::FieldChallenger;
use slop_multilinear::Point;
use slop_sumcheck::{ComponentPoly, SumcheckPoly, SumcheckPolyFirstRound};

use super::verifier::{ZkPartialSumcheckParameters, ZkPartialSumcheckProof};

/// Output packaging the evaluation claims sumcheck is reduced to needed for later prover protocols
///
/// Contains:
/// - The evaluation point
/// - Indices in the Proof Transcript for the claimed sum, total evaluation, and component poly evaluations
#[derive_where(Clone; StackedPcsProverValue<GC, MK>: Clone)]
pub struct ZkPartialSumcheckOutput<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> {
    pub eval_point: Point<GC::EF>,
    pub claimed_sum: StackedPcsProverValue<GC, MK>,
    pub total_eval: StackedPcsProverValue<GC, MK>,
    pub component_poly_evals: Vec<Vec<StackedPcsProverValue<GC, MK>>>,
}

/// Convenience function for sumcheck reduction when there is only a single polynomial and claim
pub fn zk_reduce_sumcheck_to_evaluation<GC: ZkIopCtx, MK: ZkMerkleizer<GC>>(
    poly: impl SumcheckPolyFirstRound<GC::EF>,
    context: &mut StackedPcsZkProverContext<GC, MK>,
    claim: StackedPcsProverValue<GC, MK>,
) -> (ZkPartialSumcheckOutput<GC, MK>, ZkPartialSumcheckProof<GC, StackedPcsZkProverContext<GC, MK>>)
{
    zk_reduce_sumcheck_to_evaluation_general(vec![poly], context, vec![claim], 1, GC::EF::one())
}

/// Performs a zero-knowledge sumcheck proof by reducing it to a polynomial evaluation claim.
/// given by evaluation of the polynomial at a point.
///
/// When multiple polynomials and their claims are provided, operates on a linear combination
/// given by the coefficient lambda.
///
/// `t` is to allow for future round-skipping, but is not used in the current implementation.
///
/// Adds data to the prover context as it progresses.
///
/// Returns a tuple of:
/// - `ZkPartialSumcheckOutput`: Prover-specific data (evaluation point, transcript indices)
/// - `ZkPartialSumcheckProof`: Constraint data shared with verifier (implements `ZkProtocolProof`)
///
/// # Panics
///
/// Panics if the polynomial has zero variables.
pub fn zk_reduce_sumcheck_to_evaluation_general<GC: ZkIopCtx, MK: ZkMerkleizer<GC>>(
    polys: Vec<impl SumcheckPolyFirstRound<GC::EF>>,
    context: &mut StackedPcsZkProverContext<GC, MK>,
    claims: Vec<StackedPcsProverValue<GC, MK>>,
    t: u32,
    lambda: GC::EF,
) -> (ZkPartialSumcheckOutput<GC, MK>, ZkPartialSumcheckProof<GC, StackedPcsZkProverContext<GC, MK>>)
{
    assert!(!polys.is_empty());

    // Check that all the polynomials have the same number of variables.
    let num_variables = polys[0].num_variables();
    assert!(polys.iter().all(|poly| poly.num_variables() == num_variables));

    // The first round will process the first t variables, so we need to ensure that there are at
    // least t variables.
    assert!(num_variables >= t);

    // The point at which the reduced sumcheck proof should be evaluated.
    let mut point = vec![];

    // Decomposing the sumcheck claims into values and indices.
    let claim_values = claims.iter().map(|claim| claim.value()).collect::<Vec<GC::EF>>();

    // The univariate poly messages.  This will be a rlc of the polys' univariate polys.
    let mut univariate_poly_msgs: Vec<Vec<StackedPcsProverValue<GC, MK>>> = vec![];

    let mut uni_polys: Vec<_> = polys
        .iter()
        .zip(claim_values.iter())
        .map(|(poly, claim)| poly.sum_as_poly_in_last_t_variables(Some(*claim), t as usize))
        .collect();

    let mut rlc_uni_poly = rlc_univariate_polynomials(&uni_polys, lambda);
    let degree = rlc_uni_poly.coefficients.len() - 1;
    let univariate_poly_coeff = context.add_values(&rlc_uni_poly.coefficients);
    univariate_poly_msgs.push(univariate_poly_coeff);

    let alpha: GC::EF = context.challenger().sample_ext_element();
    point.insert(0, alpha);
    let mut polys_cursor: Vec<_> =
        polys.into_iter().map(|poly| poly.fix_t_variables(alpha, t as usize)).collect();
    // The multi-variate polynomial used at the start of each sumcheck round.
    for _ in t..num_variables {
        // Get the round claims from the last round's univariate poly messages.
        let round_claims = uni_polys.iter().map(|poly| poly.eval_at_point(*point.first().unwrap()));

        uni_polys = polys_cursor
            .iter()
            .zip_eq(round_claims)
            .map(|(poly, round_claim)| poly.sum_as_poly_in_last_variable(Some(round_claim)))
            .collect();
        rlc_uni_poly = rlc_univariate_polynomials(&uni_polys, lambda);
        let univariate_poly_coeff = context.add_values(&rlc_uni_poly.coefficients);
        univariate_poly_msgs.push(univariate_poly_coeff);

        let alpha: GC::EF = context.challenger().sample_ext_element();
        point.insert(0, alpha);
        polys_cursor = polys_cursor.into_iter().map(|poly| poly.fix_last_variable(alpha)).collect();
    }

    let evals =
        uni_polys.iter().map(|poly| poly.eval_at_point(*point.first().unwrap())).collect_vec();

    let component_poly_evals: Vec<_> =
        polys_cursor.iter().map(|poly| poly.get_component_poly_evals()).collect();
    let poly_component_counts =
        component_poly_evals.iter().map(|evals| evals.len()).collect::<Vec<_>>();

    let rlc_claimed_sum = claim_values.into_iter().fold(GC::EF::zero(), |acc, x| acc * lambda + x);
    let claimed_sum = context.add_value(rlc_claimed_sum);

    let rlc_full_eval = evals.into_iter().fold(GC::EF::zero(), |acc, x| acc * lambda + x);
    let total_eval = context.add_value(rlc_full_eval);

    let mut component_poly_evals_out = Vec::with_capacity(component_poly_evals.len());
    for evals in component_poly_evals.iter() {
        component_poly_evals_out.push(context.add_values(evals));
    }
    let component_poly_evals = component_poly_evals_out;

    // Wrap protocol parameters
    let parameters: ZkPartialSumcheckParameters<GC, StackedPcsZkProverContext<GC, MK>> =
        ZkPartialSumcheckParameters {
            num_variables: num_variables - t + 1,
            degree,
            poly_component_counts,
            claim_exprs: claims,
            lambda,
            t,
        };
    // Wrap elements generated by ZkContext and FS-randomness in proof struct (self-contained with parameters)
    let constraint_data = ZkPartialSumcheckProof {
        parameters,
        univariate_poly_coeffs: univariate_poly_msgs,
        claimed_sum: claimed_sum.clone(),
        point: point.clone(),
        claimed_eval: total_eval.clone(),
        component_poly_evals: component_poly_evals.clone(),
    };

    let output = ZkPartialSumcheckOutput {
        eval_point: point.into(),
        claimed_sum,
        total_eval,
        component_poly_evals,
    };

    (output, constraint_data)
}
