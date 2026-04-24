use core::slice;

use itertools::Itertools;
use slop_algebra::{Algebra, ExtensionField, Field};
use slop_multilinear::{Mle, Point};
use thiserror::Error;

/// Error returned by `assert_zero` when eagerly-checking contexts (e.g. the
/// transparent verifier) encounter a non-zero argument. Carries the failing
/// expression so callers / panic messages can identify what failed.
#[derive(Debug)]
pub struct AssertZeroError<E: std::fmt::Debug>(pub E);

impl<E: std::fmt::Debug> std::fmt::Display for AssertZeroError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "assertion failed: expression did not evaluate to zero (got {:?})", self.0)
    }
}

impl<E: std::fmt::Debug + 'static> std::error::Error for AssertZeroError<E> {}

pub trait ConstraintCtx {
    type Field: Field;
    type Extension: ExtensionField<Self::Field>;

    type Expr: Algebra<Self::Extension> + Algebra<Self::Challenge>;
    type Challenge: ExtensionField<Self::Field> + Algebra<Self::Extension> + Into<Self::Extension>;
    type MleOracle;

    /// Error returned by `assert_zero` / `assert_a_times_b_equals_c`.
    ///
    /// Eager contexts (the transparent verifier) use a real error type like
    /// [`AssertZeroError`] that identifies the failing constraint. Deferred
    /// contexts (provers, ZK verifiers, mask counters) use
    /// [`std::convert::Infallible`] — they only queue claims for later
    /// discharge, so the assertion itself cannot fail at call time. Generic
    /// protocol code typically `.unwrap()`s the result: a no-op on `Infallible`,
    /// a panic with the failing expression on transparent failures.
    type AssertError: std::error::Error;

    fn assert_zero(&mut self, expr: Self::Expr) -> Result<(), Self::AssertError>;

    /// For contexts internally using R1CS-style constraints, there may be more efficient ways
    /// to do this beyond just assert_zero(a * b - c). Overwrite if needed.
    fn assert_a_times_b_equals_c(
        &mut self,
        a: Self::Expr,
        b: Self::Expr,
        c: Self::Expr,
    ) -> Result<(), Self::AssertError> {
        self.assert_zero(a * b - c)
    }

    /// Creates an expression from a polynomial evaluation: `poly(point)`.
    ///
    /// Computes: `coeff_0 + point * coeff_1 + ... + point^{n-1} * coeff_n`
    fn poly_eval(poly: &[Self::Expr], point: Self::Challenge) -> Self::Expr {
        let mut iter = poly.iter().rev();
        let first = iter.next().expect("poly_eval requires non-empty polynomial").clone();
        iter.fold(first, |acc, term| acc * point + term.clone())
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
pub enum TranscriptReadError {
    #[error("transcript exhausted")]
    TranscriptExhausted,
    #[error("transcript read mismatch: expected {expected}, got {got}")]
    TranscriptReadMismatch { expected: usize, got: usize },
    #[error("unspecified transcript read error")]
    TranscriptReadUnspecified,
}

/// Extension of `ConstraintCtx` that can read from the proof transcript and sample challenges.
///
/// Used during the "read" phase of a protocol, where proof data is consumed from the transcript.
/// Extends `ConstraintCtx` so that a reading context can also be used where only constraining
/// is needed.
pub trait ReadingCtx: ConstraintCtx {
    /// Read a message from the transcript into a slice of expressions.
    fn read_exact(&mut self, buf: &mut [Self::Expr]) -> Result<(), TranscriptReadError>;

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

    fn read_one(&mut self) -> Result<Self::Expr, TranscriptReadError> {
        let mut expr = Self::Expr::default();
        self.read_exact(slice::from_mut(&mut expr))?;
        Ok(expr)
    }

    fn read_next(&mut self, count: usize) -> Result<Vec<Self::Expr>, TranscriptReadError> {
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

/// Extension of `ConstraintCtx` for the prover side: everything a protocol needs
/// to drive a veil protocol through to (but not including) finalization.
///
/// This surface is what protocol code (`param.prove`, inline prover flows in
/// examples) actually calls: sending values to the transcript, sampling challenges,
/// committing MLEs. The finalization step — producing the backend-specific `Proof`
/// from the context — is an inherent method on each concrete ctx, not a trait
/// method, so that the main driver calls `ctx.prove(rng)` alongside `ctx.verify()`
/// symmetrically and each backend is free to pick its own return type.
///
/// The `commit_mle` method carries a `Standard: Distribution<Self::Field>` where
/// clause — only required at call sites that actually commit, so protocol code
/// that only touches the send / sample / to_value surface does not need to
/// propagate it.
pub trait SendingCtx: ConstraintCtx {
    /// Error returned by [`Self::commit_mle`].
    type CommitError: std::error::Error;

    /// Send a single value to the verifier (adds it to the proof transcript).
    fn send_value(&mut self, value: Self::Extension) -> Self::Expr;

    /// Send multiple values to the verifier (adds them to the proof transcript).
    fn send_values(&mut self, values: &[Self::Extension]) -> Vec<Self::Expr>;

    /// Evaluate an expression to its underlying extension-field value.
    ///
    /// Prover-only operation: on the prover side, every `Expr` carries (or can
    /// recompute) its concrete value. This is the inverse of `send_value` /
    /// the `Algebra<Extension>` lifting — it lets protocols extract the concrete
    /// value from an Expr that was built earlier (e.g. an upstream protocol's
    /// output claim, or a claim constructed via `Expr::one() * value`) without
    /// re-transmitting it on the transcript.
    fn to_value(&self, expr: &Self::Expr) -> Self::Extension;

    /// Sample a Fiat-Shamir challenge from the transcript.
    fn sample(&mut self) -> Self::Challenge;

    /// Commit to an MLE via the backend's configured polynomial-commitment scheme.
    ///
    /// The returned [`ConstraintCtx::MleOracle`] handle can be passed to
    /// [`ConstraintCtx::assert_mle_eval`] / [`ConstraintCtx::assert_mle_multi_eval`]
    /// later in the protocol.
    ///
    /// `log_num_polynomials` specifies how many stacked polynomials this MLE commit
    /// represents; backends using the stacked PCS must have been constructed to
    /// match this value.
    fn commit_mle<RNG: rand::CryptoRng + rand::Rng>(
        &mut self,
        mle: Mle<Self::Field>,
        log_num_polynomials: u32,
        rng: &mut RNG,
    ) -> Result<Self::MleOracle, Self::CommitError>
    where
        rand::distributions::Standard: rand::distributions::Distribution<Self::Field>;

    /// Sample a multilinear point
    fn sample_point(&mut self, dimension: u32) -> Point<Self::Challenge> {
        let values = (0..dimension).map(|_| self.sample()).collect::<Vec<_>>();
        Point::from(values)
    }
}
