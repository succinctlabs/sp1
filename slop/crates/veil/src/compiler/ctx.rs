use itertools::Itertools;
use slop_algebra::{Algebra, ExtensionField, Field};
use slop_multilinear::Point;

pub trait ConstraintCtx {
    type Field: Field;
    type Extension: ExtensionField<Self::Field>;

    type Expr: Algebra<Self::Extension>;
    type MleOracle;

    fn assert_zero(&mut self, expr: Self::Expr);

    /// assert_zero(a * b - c) materializes the product of a and b. This is unnecessary specifically
    /// for constraints of the form a * b = c. Use this instead to avoid the extra materialization.
    fn assert_a_times_b_equals_c(&mut self, a: Self::Expr, b: Self::Expr, c: Self::Expr);

    /// Creates an expression from a polynomial evaluation: `poly(point)`.
    ///
    /// Computes: `coeff_0 + point * coeff_1 + ... + point^{n-1} * coeff_n`
    fn poly_eval(poly: &[Self::Expr], point: Self::Expr) -> Self::Expr {
        let mut iter = poly.iter().rev();
        let first = iter.next().expect("poly_eval requires non-empty polynomial").clone();
        iter.fold(first, |acc, term| acc * point.clone() + term.clone())
    }

    /// Creates an expression from `eval(1) + eval(0)` of a polynomial.
    ///
    /// Computes: `2 * coeff_0 + coeff_1 + ... + coeff_n`
    fn eval_one_plus_eval_zero(poly: &[Self::Expr]) -> Self::Expr {
        let mut iter = poly.iter();
        let first = iter.next().expect("eval_one_plus_eval_zero requires non-empty polynomial");
        // Start with 2 * coeff_0, then add the rest
        let two_first = first.clone() + first.clone();
        iter.fold(two_first, |acc, term| acc + term.clone())
    }

    /// Creates an expression from an MLE evaluation at point.
    ///
    /// Assumes the input vec of elements' entries are the evaluations of the MLE
    /// on the hypercube in standard order.
    ///
    /// # Panics
    ///
    /// Requires exactly 2^{dim(Point)} many entries in `coeffs`.
    fn mle_eval(point: Point<Self::Expr>, coeffs: &[Self::Expr]) -> Self::Expr {
        use slop_multilinear::partial_lagrange_blocking;

        let lagrange_coeffs = partial_lagrange_blocking(&point).into_buffer().into_vec();

        let mut iter = lagrange_coeffs.into_iter().zip_eq(coeffs.iter());
        let (first_coeff, first_index) =
            iter.next().expect("mle_eval requires non-empty coefficients");
        let first = first_index.clone() * first_coeff;
        iter.fold(first, |acc, (coeff, index)| acc + index.clone() * coeff)
    }

    /// Asserts that a committed MLE evaluates to `eval_expr` at `point`.
    ///
    /// Registers an evaluation claim that will be proven/verified during
    /// the PCS proof generation/verification phase.
    ///
    /// # Arguments
    /// * `oracle` - Handle to the committed MLE (from `read_oracle`)
    /// * `point` - The evaluation point
    /// * `eval_expr` - Expression representing the claimed evaluation value
    fn assert_mle_eval(
        &mut self,
        oracle: Self::MleOracle,
        point: Point<Self::Expr>,
        eval_expr: Self::Expr,
    );
}

/// Extension of `ConstraintCtx` that can read from the proof transcript and sample challenges.
///
/// Used during the "read" phase of a protocol, where proof data is consumed from the transcript.
/// Extends `ConstraintCtx` so that a reading context can also be used where only constraining
/// is needed.
pub trait ReadingCtx: ConstraintCtx {
    /// Read a single element from the proof transcript.
    /// Returns `None` if the transcript is exhausted.
    fn read(&mut self) -> Option<Self::Expr>;

    /// Read a PCS commitment from the transcript, returning an opaque oracle handle.
    /// Returns `None` if the transcript is exhausted or parameters don't match.
    fn read_oracle(&mut self, log_width: usize, log_stacking: usize) -> Option<Self::MleOracle>;

    /// Sample a Fiat-Shamir challenge from the transcript.
    fn sample(&mut self) -> Self::Expr;
}
