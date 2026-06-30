//! Stacked MLE-decomposition helpers (block convention): given an evaluation point for a flat MLE
//! committed as a set of columns, split the point into the base-PCS opening point (the *reduced*
//! point) and the eq-coefficient combiner (the *oracle eval*) over the columns.
//!
//! The flat MLE is carved into **consecutive blocks** of height `2^log_stacking_height`, one block
//! per committed column. The column index is the **high** bits of the flat index, the within-column
//! index the **low** bits. Accordingly a point splits as
//! `point = (batch_point ∈ first dim - log_stacking_height coords, stack_point ∈ last
//! log_stacking_height coords)`, the columns are opened at `stack_point`, and
//! `f(point) = Σ_c eq(batch_point, c) · col_c(stack_point)`. This matches the convention used by
//! [`crate::StackedPcsVerifier`]'s `verify_trusted_evaluation`, the jagged layer, basefold's fixed
//! encoding width (`num_encoding_variables = log_stacking_height`), and both the transparent and ZK
//! stacked PCS paths in veil.
//!
//! The combiner spans the columns flattened in commitment order, so it works for a single
//! commitment or the union of a batch of commitments opened at the same `stack_point` — padding
//! columns (zero-filled) sit at the tail and either carry their (zero) leaves or fall off the end
//! of the coefficient vector, so they need no special handling.

use core::ops::Mul;

use itertools::Itertools;
use slop_algebra::AbstractField;
use slop_multilinear::{partial_lagrange_blocking, LinearOracleEval, Point};

/// Combine one committed row's base-field column values with stacking coefficients:
/// `Σ_c coeffs[c] · row[c]`, scaling each extension-field coefficient by its base-field value.
///
/// This is the per-row/per-query application of a stacking combiner (e.g. the coefficients of a
/// [`stacked_oracle_eval`] / [`stacked_batched_oracle_eval`] `LinearOracleEval`) to opened or
/// committed columns. It exists as a standalone helper because [`LinearOracleEval`]'s own
/// `OracleEval` impl multiplies `leaf · coeff` and so cannot be reused when the leaves are
/// base-field and the coefficients are extension-field (`F: Mul<EF>` is not defined). We instead
/// form the product as `coeff · leaf` (`EF * F`), the cheap base-field scaling (`D` base mults)
/// rather than lifting each leaf into the extension and paying a full `EF * EF` multiply. `coeffs`
/// and `row` must have equal length.
pub fn stacking_combine<F, EF>(coeffs: &[EF], row: &[F]) -> EF
where
    F: Clone,
    EF: AbstractField + Mul<F, Output = EF>,
{
    coeffs
        .iter()
        .zip_eq(row.iter())
        .map(|(c, v)| c.clone() * v.clone())
        .reduce(|acc, x| acc + x)
        .unwrap_or_else(EF::zero)
}

/// Stacking combiner: `Σ_c eq(batch_point, c) · col_c`, where `batch_point` is the **first**
/// `dim - log_stacking_height` coordinates of `point` and `c` indexes the committed columns
/// flattened in commitment order. Paired with [`stacked_reduced_point`].
pub fn stacked_oracle_eval<EF>(
    point: &Point<EF>,
    log_stacking_height: usize,
) -> LinearOracleEval<EF>
where
    EF: AbstractField + Copy,
{
    let (batch_point, _) = point.split_at(point.dimension() - log_stacking_height);
    let coeffs = partial_lagrange_blocking(&batch_point).into_buffer().into_vec();
    LinearOracleEval { coeffs }
}

/// The reduced point: the **last** `log_stacking_height` coordinates of `point`, at which the base
/// PCS opens the committed columns.
pub fn stacked_reduced_point<EF: Clone>(
    point: &Point<EF>,
    log_stacking_height: usize,
) -> Point<EF> {
    let (_, stack_point) = point.split_at(point.dimension() - log_stacking_height);
    stack_point
}

/// Combiner over the union of all columns across multiple commitments opened at the **same** reduced
/// point, with the commitments eq-batched by `selector_point` (dimension `⌈log₂ N⌉` for `N`
/// commitments).
///
/// This is exactly [`stacked_oracle_eval`] applied to `selector_point ++ point`: since
/// [`partial_lagrange`](slop_multilinear::partial_lagrange) is big-endian (first coord = most
/// significant), the resulting coefficients are `eq(selector_point, j) · eq(batch_point, c)` over
/// every `(commitment j, column c)` pair, flattened in **commitment-major** order — exactly how
/// [`LinearOracleEval`] flattens the `Rounds` of opened leaves (one round per commitment). The
/// shared reduced point is unchanged ([`stacked_reduced_point`] on either `point` or the combined
/// point gives the same last `log_stacking_height` coords).
///
/// Reduces to [`stacked_oracle_eval`] when `selector_point` is empty (a single commitment). This is
/// the eq-batching analogue of combining commitments with powers of a single challenge.
pub fn stacked_batched_oracle_eval<EF>(
    selector_point: &Point<EF>,
    point: &Point<EF>,
    log_stacking_height: usize,
) -> LinearOracleEval<EF>
where
    EF: AbstractField + Copy,
{
    let mut combined = selector_point.clone();
    combined.extend(point);
    stacked_oracle_eval(&combined, log_stacking_height)
}
