use core::slice;

use itertools::Itertools;
use slop_algebra::{Algebra, ExtensionField, Field};
use slop_multilinear::Point;
use thiserror::Error;

pub trait ConstraintCtx {
    type Field: Field;
    type Extension: ExtensionField<Self::Field>;

    type Expr: Algebra<Self::Extension> + Algebra<Self::Challenge>;
    type Challenge: Clone + Algebra<Self::Extension> + Into<Self::Extension>;
    type MleOracle;

    fn assert_zero(&mut self, expr: Self::Expr);

    /// assert_zero(a * b - c) materializes the product of a and b. This is unnecessary specifically
    /// for constraints of the form a * b = c. Use this instead to avoid the extra materialization.
    fn assert_a_times_b_equals_c(&mut self, a: Self::Expr, b: Self::Expr, c: Self::Expr);

    /// Creates an expression from a polynomial evaluation: `poly(point)`.
    ///
    /// Computes: `coeff_0 + point * coeff_1 + ... + point^{n-1} * coeff_n`
    fn poly_eval(poly: &[Self::Expr], point: Self::Challenge) -> Self::Expr {
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
    /// Default implementation delegates to `assert_mle_multi_eval` with a single claim.
    fn assert_mle_eval(
        &mut self,
        oracle: Self::MleOracle,
        point: Point<Self::Challenge>,
        eval_expr: Self::Expr,
    ) {
        self.assert_mle_multi_eval(vec![(oracle, eval_expr)], point);
    }

    /// Asserts that multiple committed MLEs evaluate to the given values at a shared point.
    ///
    /// This produces a single batched PCS proof covering all commitments,
    /// which is more efficient than calling `assert_mle_eval` once per commitment.
    fn assert_mle_multi_eval(
        &mut self,
        claims: Vec<(Self::MleOracle, Self::Expr)>,
        point: Point<Self::Challenge>,
    );
}

#[derive(Clone, Copy, Debug, Error)]
#[error("transcript exhausted, message size {0} too large")]
pub struct TranscriptExhaustedError(pub usize);

/// Extension of `ConstraintCtx` that can read from the proof transcript and sample challenges.
///
/// Used during the "read" phase of a protocol, where proof data is consumed from the transcript.
/// Extends `ConstraintCtx` so that a reading context can also be used where only constraining
/// is needed.
pub trait ReadingCtx: ConstraintCtx {
    /// Read a message from the transcript into a slice of expressions.
    fn read_exact(&mut self, buf: &mut [Self::Expr]) -> Result<(), TranscriptExhaustedError>;

    /// Read a PCS commitment from the transcript, returning an opaque oracle handle.
    ///
    /// The committed MLE has `num_encoding_variables + log_num_polynomials` total variables.
    /// It is stored as a tensor with `2^log_num_polynomials` columns, each of which is a
    /// polynomial over `num_encoding_variables` variables.
    ///
    /// # Arguments
    /// * `num_encoding_variables` — number of variables per stacked polynomial (encoding width).
    ///   Must match the value passed to [`initialize_zk_prover_and_verifier`](crate::zk::stacked_pcs::initialize_zk_prover_and_verifier)
    ///   when the PCS was set up.
    /// * `log_num_polynomials` — log2 of the number of stacked polynomials (tensor height).
    ///
    /// Returns `None` if the transcript is exhausted or parameters don't match.
    fn read_oracle(
        &mut self,
        num_encoding_variables: u32,
        log_num_polynomials: u32,
    ) -> Option<Self::MleOracle>;

    /// Sample a Fiat-Shamir challenge from the transcript.
    fn sample(&mut self) -> Self::Challenge;

    fn read_one(&mut self) -> Result<Self::Expr, TranscriptExhaustedError> {
        let mut expr = Self::Expr::default();
        self.read_exact(slice::from_mut(&mut expr))?;
        Ok(expr)
    }

    fn read_next(&mut self, count: usize) -> Result<Vec<Self::Expr>, TranscriptExhaustedError> {
        let mut values = vec![Self::Expr::default(); count];
        self.read_exact(&mut values)?;
        Ok(values)
    }

    /// Sample a multiplinear point
    fn sample_point(&mut self, dimension: u32) -> Point<Self::Challenge> {
        let values = (0..dimension).map(|_| self.sample()).collect::<Vec<_>>();
        Point::from(values)
    }
}

/// Extension of `ConstraintCtx` for the prover side: sending values and sampling challenges.
pub trait SendingCtx: ConstraintCtx {
    /// Send a single value to the verifier (adds it to the proof transcript).
    fn send_value(&mut self, value: Self::Extension) -> Self::Expr;

    /// Send multiple values to the verifier (adds them to the proof transcript).
    fn send_values(&mut self, values: &[Self::Extension]) -> Vec<Self::Expr>;

    /// Sample a Fiat-Shamir challenge from the transcript.
    fn sample(&mut self) -> Self::Challenge;

    /// Sample a multilinear point
    fn sample_point(&mut self, dimension: u32) -> Point<Self::Challenge> {
        let values = (0..dimension).map(|_| self.sample()).collect::<Vec<_>>();
        Point::from(values)
    }
}
