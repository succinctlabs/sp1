use core::slice;
use std::error::Error;
use std::fmt::Debug;

use itertools::Itertools;
use slop_algebra::{Algebra, ExtensionField, Field};
use slop_commit::{Message, Rounds};
use slop_multilinear::{Mle, OracleEval, Point};
use thiserror::Error;

pub trait ConstraintCtx {
    type Field: Field;
    type Extension: ExtensionField<Self::Field>;

    type Expr: Algebra<Self::Extension> + Algebra<Self::Challenge>;
    type Challenge: ExtensionField<Self::Field> + Algebra<Self::Extension> + Into<Self::Extension>;
    /// An opaque handle to a committed MLE. `Copy` because handles are cheap indices into the
    /// context's commitment records, which lets the `assert_mle_*` API take them as slices.
    type MleCommit: Copy;

    /// Error returned by `assert_zero` / `assert_a_times_b_equals_c` / the `assert_mle_*` methods.
    ///
    /// Contexts that discharge MLE-eval openings eagerly (the ZK and transparent prover/verifier)
    /// use a real error type carrying the PCS / assertion failure. The mask counter, which only
    /// tallies and never actually checks anything, uses [`std::convert::Infallible`]. Generic
    /// protocol code propagates the result with `?` (wrapping it in
    /// [`ProtocolError::Assert`](crate::protocols::ProtocolError::Assert)).
    type AssertError: Error;

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
    fn mle_eval(point: &Point<Self::Expr>, coeffs: &[Self::Expr]) -> Self::Expr {
        use slop_multilinear::partial_lagrange_blocking;

        let lagrange_coeffs = partial_lagrange_blocking(point).into_buffer().into_vec();

        let mut iter = lagrange_coeffs.into_iter().zip_eq(coeffs.iter());
        let (first_coeff, first_index) =
            iter.next().expect("mle_eval requires non-empty coefficients");
        let first = first_index.clone() * first_coeff;
        iter.fold(first, |acc, (coeff, index)| acc + index.clone() * coeff)
    }

    /// Asserts that a committed MLE evaluates to `eval_expr` at `point`, and eagerly proves
    /// (prover) or verifies (verifier) the hash part of the evaluation right here.
    ///
    /// The required linear constraints (like all others) are batched and proven/checked once
    /// at the very end, in `prove`/`verify`.
    ///
    /// Default implementation delegates to `assert_mle_multi_eval` with a single claim.
    fn assert_mle_eval(
        &mut self,
        oracle: Self::MleCommit,
        point: &Point<Self::Challenge>,
        eval_expr: Self::Expr,
    ) -> Result<(), Self::AssertError> {
        self.assert_mle_multi_eval(vec![(oracle, eval_expr)], point)
    }

    /// Asserts that multiple committed MLEs evaluate to the given values at a shared point, eagerly
    /// proving/verifying the hash part of the opening (see [`Self::assert_mle_eval`]).
    ///
    /// This produces a single batched PCS proof covering all commitments,
    /// which is more efficient than calling `assert_mle_eval` once per commitment.
    fn assert_mle_multi_eval(
        &mut self,
        claims: Vec<(Self::MleCommit, Self::Expr)>,
        point: &Point<Self::Challenge>,
    ) -> Result<(), Self::AssertError>;

    /// Like [`Self::assert_mle_eval`] but with a caller-supplied MLE decomposition.
    ///
    /// `reduced_point` is the inner point at which the PCS opens the committed columns, and
    /// `oracle_eval` is the combiner mapping the column sub-evaluations to the original evaluation
    /// (`eval_expr == oracle_eval(column_evals)`). They are a matched pair. The plain
    /// [`Self::assert_mle_eval`] selects the default (eq-coefficient stacking) decomposition.
    ///
    /// The combiner is applied at this (outer) expression type — the PCS opening returns the column
    /// sub-evaluations and this context combines them — so `oracle_eval` may be any
    /// [`OracleEval<Self::Expr, Self::Expr>`], including a non-linear one or a plain closure.
    ///
    /// This is the one-claim specialization of [`Self::assert_mle_multi_eval_with_oracle`].
    fn assert_mle_eval_with_oracle<O: OracleEval<Self::Expr, Self::Expr>>(
        &mut self,
        commits: &[Self::MleCommit],
        reduced_point: &Point<Self::Challenge>,
        reduced_eval: Self::Expr,
        oracle_eval: O,
    ) -> Result<(), Self::AssertError> {
        self.assert_mle_multi_eval_with_oracle(
            vec![MleEvalClaim {
                commits: Rounds { rounds: commits.to_vec() },
                claimed_eval: reduced_eval,
                oracle_eval,
            }],
            reduced_point,
        )
    }

    /// The general PCS evaluation assertion: a batch of N (possibly *cross-commitment*) claims that
    /// share a common reduced `point`.
    ///
    /// The point being shared is exactly what preserves the multi-eval batching: every commitment
    /// read by any claim is opened *together* in a single base proof at `point`. A claim reading
    /// several commitments is *cross-commitment*: its combiner runs across all of its commitments'
    /// columns (e.g. `f(p0) + g(p1)` for full points `p0`, `p1` sharing their reduced coordinates).
    ///
    /// For claim `c`: `c.claimed_eval == c.oracle_eval(columns)`, where `columns` is the `Rounds` of
    /// `c`'s opened commitments' column sub-evaluations, in `c.commits` order.
    ///
    /// Every other `assert_mle_*` method specializes this one: the `with_oracle` forms supply custom
    /// decompositions directly, while the plain forms build the default (eq-coefficient stacking)
    /// decomposition. Every commitment opened across the whole request must be distinct (each is
    /// opened at most once).
    fn assert_mle_multi_eval_with_oracle<O: OracleEval<Self::Expr, Self::Expr>>(
        &mut self,
        claims: Vec<MleEvalClaim<Self::MleCommit, Self::Expr, O>>,
        point: &Point<Self::Challenge>,
    ) -> Result<(), Self::AssertError>;
}

/// A single (possibly cross-commitment) MLE-eval claim for
/// [`ConstraintCtx::assert_mle_multi_eval_with_oracle`].
///
/// The claim asserts `claimed_eval == oracle_eval(columns)`, where `columns` are the column
/// sub-evaluations of the MLEs in `commits`, all opened at the shared `point` argument. A one-round
/// `commits` is an ordinary single-commitment claim; a multi-round `commits` is a
/// *cross-commitment* claim whose value depends on several commitments jointly.
pub struct MleEvalClaim<Commit, Expr, O> {
    /// The commitments this claim reads. The combiner receives their columns as a
    /// `slop_commit::Rounds` in this order.
    pub commits: Rounds<Commit>,
    /// The single claimed evaluation value.
    pub claimed_eval: Expr,
    /// The combiner mapping the commitments' column sub-evaluations to `claimed_eval`.
    pub oracle_eval: O,
}

#[derive(Clone, Copy, Debug, Error)]
pub enum TranscriptReadError {
    #[error("transcript exhausted")]
    TranscriptExhausted,
    #[error("transcript read mismatch: expected {expected}, got {got}")]
    TranscriptReadMismatch { expected: usize, got: usize },
    #[error("unspecified transcript read error")]
    TranscriptReadUnspecified,
    /// A transcript read was attempted after an MLE-eval claim (PCS opening) was made. PCS
    /// openings are *terminal*: they consume the post-main-protocol Fiat-Shamir state, so any
    /// further `read_*` would silently read from the wrong place. All reads must precede every
    /// `assert_mle_eval` / `assert_mle_multi_eval`.
    #[error(
        "transcript read attempted after a PCS eval claim; all transcript reads must precede any \
         assert_mle_eval (PCS openings are terminal)"
    )]
    ReadAfterPcsClaim,
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
    /// The committed MLE has `num_variables` total variables. It is stored as a tensor
    /// with `2^log_num_polynomials` columns, each of which is a polynomial over the PCS's
    /// fixed `num_encoding_variables` variables, where
    /// `log_num_polynomials = num_variables - num_encoding_variables`.
    ///
    /// # Arguments
    /// * `num_variables` — total number of variables of the committed MLE. The PCS's
    ///   `num_encoding_variables` (fixed at [`initialize_zk_prover_and_verifier`](crate::zk::stacked_pcs::initialize_zk_prover_and_verifier))
    ///   is subtracted from this to recover the number of stacked polynomials.
    ///
    /// Returns `None` if the transcript is exhausted or parameters don't match.
    fn read_oracle(&mut self, num_variables: u32) -> Option<Self::MleCommit>;

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
    type CommitError: Error;

    /// The fixed encoding width of the backend's PCS: every committed column is a polynomial over
    /// this many variables, so [`Self::commit_mle`] expects its input pre-stacked into
    /// `[2^num_encoding_variables, num_columns]` block columns (see
    /// `slop_stacked::stack_multilinear`). Panics if the context was built without a PCS.
    fn num_encoding_variables(&self) -> u32;

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
    /// The MLE is passed as a [`Message`] so the caller can retain a cheap (`Arc`-backed)
    /// handle to its data without an expensive deep clone; the buffer is only read, and is
    /// moved (rather than copied) when the caller holds no other reference.
    ///
    /// The MLE must be **pre-stacked**, given as one or more data components committed jointly under
    /// a single commitment: each `mle[i]` is a `[2^num_encoding_variables, cols_i]` block-column
    /// tensor (column `ℓ` = a consecutive block `f_ℓ`), as produced by
    /// `slop_stacked::stack_multilinear` from a flat evaluation vector — or held directly by a
    /// column-major producer (e.g. jagged's `LongMle`). Their columns concatenate, in order, into
    /// the commitment's column set; the common case is a single component.
    /// `num_encoding_variables` is the fixed encoding width the backend's PCS was constructed with,
    /// and must equal `mle[i].num_variables()` for every component.
    fn commit_mle<RNG: rand::CryptoRng + rand::Rng>(
        &mut self,
        mle: Message<Mle<Self::Field>>,
        rng: &mut RNG,
    ) -> Result<Self::MleCommit, Self::CommitError>
    where
        rand::distributions::Standard: rand::distributions::Distribution<Self::Field>;

    /// Sample a multilinear point
    fn sample_point(&mut self, dimension: u32) -> Point<Self::Challenge> {
        let values = (0..dimension).map(|_| self.sample()).collect::<Vec<_>>();
        Point::from(values)
    }
}
