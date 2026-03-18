use std::ops::{Add, Mul, Sub};

use itertools::Itertools;
use slop_algebra::AbstractField;
use slop_multilinear::Point;

pub trait ConstraintBuilder {
    type MleOracle;

    type Field: AbstractField;

    type Expr: AbstractField
        + Add<Self::Field, Output = Self::Expr>
        + Sub<Self::Field, Output = Self::Expr>
        + Mul<Self::Field, Output = Self::Expr>;

    fn assert_zero(&mut self, expr: Self::Expr);

    /// assert_zero(a * b - c) materializes the product of a and b. This is unnecessary specifically
    /// for constraints of the form a * b = c. Use this instead to avoid the extra materialization.
    fn assert_a_times_b_equals_c(&mut self, a: Self::Expr, b: Self::Expr, c: Self::Expr);

    /// Add a constant as an expression in the context.
    fn cst(&mut self, value: Self::Field) -> Self::Expr;

    #[cfg(sp1_debug_constraints)]
    fn name_last_lin_constraint(&self, _name: impl Into<String>) {}

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
    /// * `commitment_index` - Index of the committed MLE (from `commit_mle` or `read_next_pcs_commitment`)
    /// * `point` - The evaluation point
    /// * `eval_expr` - Expression representing the claimed evaluation value
    fn assert_mle_eval(
        &mut self,
        oracle: Self::MleOracle,
        point: Point<Self::Expr>,
        eval_expr: Self::Expr,
    );
}
