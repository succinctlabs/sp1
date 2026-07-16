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
//!
//! The fused rounds are proven by [`slop_sumcheck::reduce_sumcheck_to_evaluation`] with a
//! lookahead depth of `t = 2`: [`ZeroCheckPoly`]'s first-round implementation computes the grid
//! (and the first message) in [`zerocheck_sum_as_poly_in_last_two_variables`], and
//! [`zerocheck_fix_last_variable_with_lookahead`] hands the second message over to the
//! next-round polynomial.

use itertools::Itertools;
use slop_algebra::{
    interpolate_univariate_polynomial, ExtensionField, Field, UnivariatePolynomial,
};
use slop_multilinear::Mle;
use slop_sumcheck::SumcheckPolyBase;

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
#[derive(Clone)]
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

/// The first-round message of the zerocheck sumcheck with a two-round lookahead (`t = 2`).
///
/// Computes the bivariate grid evaluations in a single pass over the base-field traces and
/// caches them on the polynomial, from where [`zerocheck_fix_last_variable_with_lookahead`]
/// interpolates the second-round message once the first challenge is known.
pub(crate) fn zerocheck_sum_as_poly_in_last_two_variables<F, EF, A>(
    poly: &ZeroCheckPoly<F, F, EF, A>,
    claim: Option<EF>,
) -> UnivariatePolynomial<EF>
where
    F: Field,
    EF: ExtensionField<F>,
    A: ZerocheckAir<F, EF>,
{
    let evals = poly.bivariate_evals.get_or_init(|| zerocheck_bivariate_evals(poly));
    let message = zerocheck_first_round_message(poly, evals.as_ref());
    if let Some(claim) = claim {
        debug_assert_eq!(
            message.eval_one_plus_eval_zero(),
            claim,
            "first round message inconsistent with the claim"
        );
    }
    message
}

/// Fixes the last variable to the first-round challenge under a two-round lookahead (`t = 2`).
///
/// The second-round message `h(X) = p(X, alpha)` is interpolated from the grid cached by
/// [`zerocheck_sum_as_poly_in_last_two_variables`] and carried over to the folded polynomial,
/// so the second round requires no pass over the trace.
pub(crate) fn zerocheck_fix_last_variable_with_lookahead<F, EF, A>(
    mut poly: ZeroCheckPoly<F, F, EF, A>,
    alpha: EF,
) -> ZeroCheckPoly<EF, F, EF, A>
where
    F: Field,
    EF: ExtensionField<F>,
    A: ZerocheckAir<F, EF>,
{
    let evals = poly.bivariate_evals.take().unwrap_or_else(|| zerocheck_bivariate_evals(&poly));
    let message = zerocheck_second_round_message(&poly, evals.as_ref(), alpha);
    let mut folded = zerocheck_fix_last_variable(poly, alpha);
    folded.lookahead_message = Some(message);
    folded
}
