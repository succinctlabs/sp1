//! Grid interpolation for the fused first two rounds of the zerocheck sumcheck.
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
//! produced by a round-by-round prover, so the protocol and the verifier are unchanged.
//!
//! The zerocheck kernels assemble the grid from their outputs, RLC'ed over the shard's chips
//! (which is fine since the message assembly is linear in the grid); this module interpolates
//! the two round messages from the assembled grid.

use slop_algebra::{
    interpolate_univariate_polynomial, ExtensionField, Field, UnivariatePolynomial,
};

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

/// The first-round message `g(Y) = p(0, Y) + p(1, Y)` computed from the bivariate grid
/// evaluations `grid[ix][iy]` at the nodes `(ZEROCHECK_NODE_XS[ix], ZEROCHECK_NODE_XS[iy])` of
/// the last two variables (the first coordinate corresponds to the second-to-last variable),
/// where `z_a` and `z_b` are the second-to-last and last coordinates of the zerocheck point.
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
