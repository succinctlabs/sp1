//! A fused implementation of the first two rounds of the zerocheck sumcheck.
//!
//! Instead of computing the first-round message from the full trace and the second-round message
//! from the trace folded by the first challenge, the prover evaluates the *bivariate* polynomial
//!
//! `p(X, Y) = sum_i eq_zeta(i || X || Y) * F(i || X || Y)`,
//!
//! where `F` is the constraint polynomial plus the GKR opening batch (with the padded row
//! correction), on a 4x4 grid of interpolation nodes in a single pass over the base-field traces.
//! The first-round message is `g(Y) = p(0, Y) + p(1, Y)` and, after sampling the challenge
//! `alpha`, the second-round message `h(X) = p(X, alpha)` is obtained from the stored grid by
//! interpolation, without a second pass over the trace. Both messages are identical to the ones
//! produced by the round-by-round prover, so the protocol and the verifier are unchanged.
//!
//! The benefit is that the second round's constraint evaluations happen on interpolations of
//! *base-field* rows, instead of on rows of the extension-field trace obtained by folding with
//! the first-round challenge. Moreover, the constraints vanish at the four grid nodes with
//! `X, Y ∈ {0, 1}` (on real rows they hold, and on padded rows their value is cancelled exactly
//! by the geq correction), so those nodes only require the GKR opening batch, which is linear in
//! the trace and hence bilinear in `(X, Y)`.

use itertools::Itertools;
use slop_algebra::{
    interpolate_univariate_polynomial, rlc_univariate_polynomials, AbstractExtensionField,
    ExtensionField, Field, UnivariatePolynomial,
};
use slop_challenger::{FieldChallenger, VariableLengthChallenger};
use slop_multilinear::Mle;
use slop_sumcheck::{
    reduce_sumcheck_to_evaluation, ComponentPoly, PartialSumcheckProof, SumcheckPoly,
    SumcheckPolyBase,
};

use super::{zerocheck_fix_last_variable, ZeroCheckPoly, ZerocheckAir};

/// The interpolation nodes used in each of the last two variables. Together with the known root
/// of the eq term, they determine the degree-4 round messages. The non-boolean nodes are chosen
/// so that the row interpolations only require additions and doublings.
pub const ZEROCHECK_NODE_XS: [u32; 4] = [0, 1, 2, 4];

/// The grid indices `(ix, iy)` into [`ZEROCHECK_NODE_XS`] of the nodes at which the constraint
/// polynomial must be evaluated, i.e. all nodes outside the boolean square `{0, 1}^2`. The order
/// matches the node rows produced by the interpolation in the zerocheck kernels.
pub const ZEROCHECK_CONSTRAINT_NODES: [(usize, usize); 12] = [
    (0, 2),
    (0, 3),
    (1, 2),
    (1, 3),
    (2, 0),
    (2, 1),
    (2, 2),
    (2, 3),
    (3, 0),
    (3, 1),
    (3, 2),
    (3, 3),
];

/// The evaluations, on the grid [`ZEROCHECK_NODE_XS`]`^2` of the last two variables, of the
/// zerocheck sumcheck polynomial with all other variables summed over the boolean hypercube,
/// excluding the eq factors in the last two variables and the `eq_adjustment`.
///
/// `grid[ix][iy]` is the evaluation at `(ZEROCHECK_NODE_XS[ix], ZEROCHECK_NODE_XS[iy])`, where
/// the first coordinate corresponds to the second-to-last variable.
pub struct ZerocheckBivariateEvals<EF> {
    grid: [[EF; 4]; 4],
}

/// The evaluations of `eq(z, .)` at the grid nodes [`ZEROCHECK_NODE_XS`].
fn eq_at_nodes<F: Field, EF: ExtensionField<F>>(z: EF) -> [EF; 4] {
    [
        EF::one() - z,
        z,
        z * F::from_canonical_usize(3) - EF::one(),
        z * F::from_canonical_usize(7) - F::from_canonical_usize(3),
    ]
}

/// The root of `eq(z, .)`, at which the round message is known to vanish.
fn eq_root<F: Field, EF: ExtensionField<F>>(z: EF) -> EF {
    (EF::one() - z) / (EF::one() - z.double())
}

/// Computes the bivariate grid evaluations for the first two zerocheck rounds, in a single pass
/// over the trace. Returns `None` for a fully padded chip, whose round messages are zero.
fn zerocheck_bivariate_evals<F, EF, A>(
    poly: &ZeroCheckPoly<F, F, EF, A>,
) -> Option<ZerocheckBivariateEvals<EF>>
where
    F: Field,
    EF: ExtensionField<F>,
    A: ZerocheckAir<F, EF>,
{
    let num_real_entries = poly.main_columns.num_real_entries();
    if num_real_entries == 0 {
        return None;
    }
    debug_assert!(poly.num_variables() >= 2);

    let (rest_point, _) = poly.zeta.split_at(poly.zeta.dimension() - 2);

    let partial_lagrange: Mle<EF> = Mle::partial_lagrange(&rest_point);

    let (constraint_sums, gkr_sums) = poly.air_data.sum_as_poly_in_last_two_variables(
        &partial_lagrange,
        poly.preprocessed_columns.as_ref(),
        &poly.main_columns,
    );

    // The GKR opening batch is linear in the trace values, hence bilinear in the last two
    // variables: its values at the four boolean nodes determine it on the whole grid.
    let [gkr_00, gkr_01, gkr_10, gkr_11] = gkr_sums;
    let gkr_x = gkr_10 - gkr_00;
    let gkr_y = gkr_01 - gkr_00;
    let gkr_xy = gkr_11 - gkr_10 - gkr_01 + gkr_00;

    // Quadruples of fully padded rows cancel exactly against the geq correction and are not
    // summed; the only quadruple needing a correction is the one straddling the padding boundary.
    let threshold_quad = num_real_entries.div_ceil(4) - 1;
    let lagrange_threshold_eval = partial_lagrange.guts().as_buffer().as_slice()[threshold_quad];

    let mut grid = [[EF::zero(); 4]; 4];
    grid[0][0] = gkr_00;
    grid[0][1] = gkr_01;
    grid[1][0] = gkr_10;
    grid[1][1] = gkr_11;

    for (&(ix, iy), constraint_sum) in ZEROCHECK_CONSTRAINT_NODES.iter().zip_eq(constraint_sums) {
        let x = EF::from_canonical_u32(ZEROCHECK_NODE_XS[ix]);
        let y = EF::from_canonical_u32(ZEROCHECK_NODE_XS[iy]);
        let gkr_eval = gkr_00 + gkr_x * x + gkr_y * y + gkr_xy * (x * y);
        // The geq polynomial with its last two variables fixed to the node, at the straddling
        // quadruple.
        let geq_eval = poly
            .virtual_geq
            .fix_last_variable(y)
            .fix_last_variable(x)
            .eval_at_usize(threshold_quad);
        grid[ix][iy] = constraint_sum + gkr_eval
            - poly.padded_row_adjustment * lagrange_threshold_eval * geq_eval;
    }

    Some(ZerocheckBivariateEvals { grid })
}

/// The first-round message `g(Y) = p(0, Y) + p(1, Y)` computed from the bivariate grid
/// evaluations `grid[ix][iy]` (see [`ZerocheckBivariateEvals`]), where `z_a` and `z_b` are the
/// second-to-last and last coordinates of the zerocheck point.
///
/// This is shared with the GPU prover, which assembles the same grid from its kernels' outputs
/// (RLC'ed over the shard's chips, which is fine since the assembly is linear in the grid).
pub fn zerocheck_first_round_message_from_grid<F, EF>(
    grid: &[[EF; 4]; 4],
    z_a: EF,
    z_b: EF,
    eq_adjustment: EF,
) -> UnivariatePolynomial<EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    let eq_y = eq_at_nodes::<F, EF>(z_b);

    let mut xs = ZEROCHECK_NODE_XS.iter().map(|&v| EF::from_canonical_u32(v)).collect::<Vec<_>>();
    let mut ys = (0..4)
        .map(|iy| {
            // Summing `X` over `{0, 1}` leaves the linear eq factor in `X` evaluated at `z_a`.
            let summed = (EF::one() - z_a) * grid[0][iy] + z_a * grid[1][iy];
            eq_adjustment * eq_y[iy] * summed
        })
        .collect::<Vec<_>>();

    xs.push(eq_root::<F, EF>(z_b));
    ys.push(EF::zero());

    interpolate_univariate_polynomial(&xs, &ys)
}

/// The second-round message `h(X) = p(X, alpha)` computed from the bivariate grid evaluations,
/// where `alpha` is the challenge sampled after the first round. See
/// [`zerocheck_first_round_message_from_grid`] for the arguments.
pub fn zerocheck_second_round_message_from_grid<F, EF>(
    grid: &[[EF; 4]; 4],
    z_a: EF,
    z_b: EF,
    eq_adjustment: EF,
    alpha: EF,
) -> UnivariatePolynomial<EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    // Lagrange interpolation weights for evaluating a cubic given at the grid nodes at `alpha`.
    let node_points = ZEROCHECK_NODE_XS.map(EF::from_canonical_u32);
    let weights: [EF; 4] = std::array::from_fn(|k| {
        let (numerator, denominator) =
            (0..4).filter(|&j| j != k).fold((EF::one(), EF::one()), |(num, denom), j| {
                (num * (alpha - node_points[j]), denom * (node_points[k] - node_points[j]))
            });
        numerator * denominator.inverse()
    });

    let eq_x = eq_at_nodes::<F, EF>(z_a);
    let eq_y_at_alpha = z_b * alpha + (EF::one() - z_b) * (EF::one() - alpha);

    let mut xs = node_points.to_vec();
    let mut ys = (0..4)
        .map(|ix| {
            let bivariate_at_alpha = (0..4).map(|iy| weights[iy] * grid[ix][iy]).sum::<EF>();
            eq_adjustment * eq_y_at_alpha * eq_x[ix] * bivariate_at_alpha
        })
        .collect::<Vec<_>>();

    xs.push(eq_root::<F, EF>(z_a));
    ys.push(EF::zero());

    interpolate_univariate_polynomial(&xs, &ys)
}

/// The first-round message `g(Y) = p(0, Y) + p(1, Y)` obtained from the grid evaluations.
fn zerocheck_first_round_message<F, EF, A>(
    poly: &ZeroCheckPoly<F, F, EF, A>,
    evals: Option<&ZerocheckBivariateEvals<EF>>,
) -> UnivariatePolynomial<EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    let Some(evals) = evals else {
        // NOTE: We hard-code the degree of the zerocheck to be three here. This is important to
        // get the correct shape of a dummy proof.
        return UnivariatePolynomial::zero(4);
    };

    let (_, last_two) = poly.zeta.split_at(poly.zeta.dimension() - 2);
    let z_a = *last_two[0];
    let z_b = *last_two[1];

    zerocheck_first_round_message_from_grid::<F, EF>(&evals.grid, z_a, z_b, poly.eq_adjustment)
}

/// The second-round message `h(X) = p(X, alpha)` obtained from the grid evaluations, where
/// `alpha` is the challenge sampled after the first round.
fn zerocheck_second_round_message<F, EF, A>(
    poly: &ZeroCheckPoly<F, F, EF, A>,
    evals: Option<&ZerocheckBivariateEvals<EF>>,
    alpha: EF,
) -> UnivariatePolynomial<EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    let Some(evals) = evals else {
        return UnivariatePolynomial::zero(4);
    };

    let (_, last_two) = poly.zeta.split_at(poly.zeta.dimension() - 2);
    let z_a = *last_two[0];
    let z_b = *last_two[1];

    zerocheck_second_round_message_from_grid::<F, EF>(
        &evals.grid,
        z_a,
        z_b,
        poly.eq_adjustment,
        alpha,
    )
}

/// Proves the zerocheck sumcheck, reducing it to a claim about the evaluations of the trace
/// columns at a point.
///
/// This produces exactly the same transcript and proof as
/// [`slop_sumcheck::reduce_sumcheck_to_evaluation`] applied to the zerocheck polynomials, but
/// computes the first two round messages together from a single pass over the base-field traces.
///
/// # Panics
/// Panics if `polys` is empty or if the polynomials do not all have the same number of variables.
pub fn zerocheck_reduce_sumcheck_to_evaluation<F, EF, A, Challenger>(
    polys: Vec<ZeroCheckPoly<F, F, EF, A>>,
    challenger: &mut Challenger,
    claims: Vec<EF>,
    lambda: EF,
) -> (PartialSumcheckProof<EF>, Vec<Vec<EF>>)
where
    F: Field,
    EF: ExtensionField<F> + Send + Sync,
    A: ZerocheckAir<F, EF>,
    Challenger: FieldChallenger<F>,
{
    assert!(!polys.is_empty());
    let num_variables = polys[0].num_variables();
    assert!(polys.iter().all(|poly| poly.num_variables() == num_variables));

    // The fused first two rounds require at least two variables.
    if num_variables < 2 {
        return reduce_sumcheck_to_evaluation(polys, challenger, claims, 1, lambda);
    }

    // The point at which the reduced sumcheck proof should be evaluated.
    let mut point = vec![];

    // The univariate poly messages.  This will be a rlc of the polys' univariate polys.
    let mut univariate_poly_msgs: Vec<UnivariatePolynomial<EF>> = vec![];

    // Evaluate the bivariate round polynomial of each chip on the interpolation grid.
    let bivariate_evals = polys.iter().map(zerocheck_bivariate_evals).collect::<Vec<_>>();

    // First round message.
    let mut uni_polys: Vec<_> = polys
        .iter()
        .zip(bivariate_evals.iter())
        .map(|(poly, evals)| zerocheck_first_round_message(poly, evals.as_ref()))
        .collect();

    #[cfg(debug_assertions)]
    for (uni_poly, claim) in uni_polys.iter().zip_eq(claims.iter()) {
        debug_assert_eq!(
            uni_poly.eval_one_plus_eval_zero(),
            *claim,
            "first round message inconsistent with the claim"
        );
    }

    let mut rlc_uni_poly = rlc_univariate_polynomials(&uni_polys, lambda);
    let coefficients = rlc_uni_poly
        .coefficients
        .iter()
        .flat_map(AbstractExtensionField::as_base_slice)
        .copied()
        .collect_vec();
    challenger.observe_constant_length_slice(&coefficients);
    univariate_poly_msgs.push(rlc_uni_poly);

    let alpha: EF = challenger.sample_ext_element();
    point.insert(0, alpha);

    // Second round message, obtained from the stored grid without a pass over the traces.
    uni_polys = polys
        .iter()
        .zip(bivariate_evals.iter())
        .map(|(poly, evals)| zerocheck_second_round_message(poly, evals.as_ref(), alpha))
        .collect();

    rlc_uni_poly = rlc_univariate_polynomials(&uni_polys, lambda);
    challenger.observe_constant_length_extension_slice(&rlc_uni_poly.coefficients);
    univariate_poly_msgs.push(rlc_uni_poly);

    let alpha_2: EF = challenger.sample_ext_element();
    point.insert(0, alpha_2);

    // Fix the last two variables to the sampled challenges.
    let mut polys_cursor: Vec<_> = polys
        .into_iter()
        .map(|poly| zerocheck_fix_last_variable(zerocheck_fix_last_variable(poly, alpha), alpha_2))
        .collect();

    // The remaining rounds proceed exactly as in the generic sumcheck prover.
    for _ in 2..num_variables as usize {
        let round_claims = uni_polys.iter().map(|poly| poly.eval_at_point(*point.first().unwrap()));

        uni_polys = polys_cursor
            .iter()
            .zip_eq(round_claims)
            .map(|(poly, round_claim)| poly.sum_as_poly_in_last_variable(Some(round_claim)))
            .collect();
        let rlc_uni_poly = rlc_univariate_polynomials(&uni_polys, lambda);
        challenger.observe_constant_length_extension_slice(&rlc_uni_poly.coefficients);

        univariate_poly_msgs.push(rlc_uni_poly);

        let alpha: EF = challenger.sample_ext_element();
        point.insert(0, alpha);
        polys_cursor = polys_cursor.into_iter().map(|poly| poly.fix_last_variable(alpha)).collect();
    }

    let evals =
        uni_polys.iter().map(|poly| poly.eval_at_point(*point.first().unwrap())).collect_vec();

    let component_poly_evals: Vec<_> =
        polys_cursor.iter().map(ComponentPoly::get_component_poly_evals).collect();

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
