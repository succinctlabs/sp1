use slop_algebra::AbstractField;
use slop_sumcheck::{ComponentPoly, SumcheckPoly, SumcheckPolyFirstRound};
use thiserror::Error;

use crate::compiler::{ConstraintCtx, ReadingCtx, SendingCtx, TranscriptExhaustedError};

#[derive(Debug, Error)]
pub enum SumcheckError {
    #[error("sumcheck requires at least one variable, got 0")]
    NoVariables,
    #[error("sumcheck proof has no rounds")]
    EmptyProof,
    #[error("unexpected end of transcript")]
    TranscriptExhausted(#[from] TranscriptExhaustedError),
}

/// Parameters for a sumcheck protocol instance.
///
/// Static shape only — no field values and no context-dependent data.
pub struct SumcheckParam {
    /// Number of variables in the sumcheck.
    pub num_variables: u32,
    /// Degree of the composition polynomial.
    pub degree: usize,
    /// Number of component polynomial evaluations sent after the sumcheck rounds.
    /// Set to 0 if component evals are not needed.
    pub num_component_evals: usize,
}

/// Input claim: "the sum of the composition polynomial over `{0,1}^n` equals `claimed_sum`."
///
/// Not transmitted on the transcript. Supplied by the caller to `build_constraints`
/// either as a public constant (e.g. `SumcheckInputClaim::zero()` for zerocheck) or as an
/// expression piped through from an upstream protocol's output claim.
#[derive(Clone)]
pub struct SumcheckInputClaim<C: ConstraintCtx> {
    pub claimed_sum: C::Expr,
}

impl<C: ConstraintCtx> SumcheckInputClaim<C> {
    /// Construct a claim that asserts the hypercube sum is zero.
    pub fn zero() -> Self {
        Self { claimed_sum: C::Expr::zero() }
    }

    /// Construct a claim from a concrete extension-field value.
    ///
    /// The value is lifted to an `Expr` via `Expr::one() * value` — it is NOT sent
    /// on the transcript. Use this when the claim value is available locally
    /// (e.g. computed from witness data on the prover side, or from agreed public
    /// inputs on the verifier side).
    pub fn from_value(value: C::Extension) -> Self {
        Self { claimed_sum: C::Expr::one() * value }
    }
}

/// Output claim: "the composition polynomial evaluates to `claimed_eval` at random
/// point `point`, with component polynomials evaluating to `component_evals` at `point`."
///
/// This is the reduced claim handed off to downstream protocols (typically an MLE PCS
/// opening or another sumcheck).
pub struct SumcheckOutputClaim<C: ConstraintCtx> {
    /// Fiat-Shamir challenges (evaluation point), stored inner-to-outer.
    pub point: Vec<C::Challenge>,
    /// Claimed evaluation at the random point (output of the sumcheck).
    pub claimed_eval: C::Expr,
    /// Individual component polynomial evaluations at the random point.
    /// Empty if `num_component_evals` was 0.
    pub component_evals: Vec<C::Expr>,
}

/// Returned by `prove` / `read`. Carries the output claim plus the per-round univariate
/// polynomial coefficients needed by `build_constraints` to emit round-consistency checks.
pub struct SumcheckView<C: ConstraintCtx> {
    pub out_claim: SumcheckOutputClaim<C>,
    pub(crate) univariate_poly_coeffs: Vec<Vec<C::Expr>>,
}

impl SumcheckParam {
    pub fn new(num_variables: u32, degree: usize) -> Self {
        Self { num_variables, degree, num_component_evals: 0 }
    }

    /// Create a sumcheck param that also sends/reads component evaluations.
    pub fn with_component_evals(
        num_variables: u32,
        degree: usize,
        num_component_evals: usize,
    ) -> Self {
        Self { num_variables, degree, num_component_evals }
    }

    /// Read the sumcheck proof from the transcript.
    ///
    /// The input claim is NOT read from the transcript; it is passed to
    /// `build_constraints` separately by the caller.
    pub fn read<C: ReadingCtx>(&self, ctx: &mut C) -> Result<SumcheckView<C>, SumcheckError> {
        if self.num_variables == 0 {
            return Err(SumcheckError::NoVariables);
        }

        let mut alphas = Vec::with_capacity(self.num_variables as usize);
        let mut univariate_poly_coeffs = Vec::with_capacity(self.num_variables as usize);

        for _ in 0..self.num_variables {
            let coeffs = ctx.read_next(self.degree + 1)?;
            let alpha = ctx.sample();
            alphas.push(alpha);
            univariate_poly_coeffs.push(coeffs);
        }

        // Alphas are collected outer-to-inner, reverse for point representation.
        alphas.reverse();

        let claimed_eval = ctx.read_one()?;

        let component_evals = if self.num_component_evals > 0 {
            ctx.read_next(self.num_component_evals)?
        } else {
            vec![]
        };

        Ok(SumcheckView {
            out_claim: SumcheckOutputClaim { point: alphas, claimed_eval, component_evals },
            univariate_poly_coeffs,
        })
    }

    /// Run the prover side of sumcheck, sending round polynomials through the context.
    ///
    /// `in_claim.claimed_sum` is NOT transmitted on the transcript. The prover extracts
    /// the concrete value it needs for witness computation via `ctx.to_value`.
    pub fn prove<C: SendingCtx>(
        &self,
        in_claim: &SumcheckInputClaim<C>,
        poly: impl SumcheckPolyFirstRound<C::Extension>,
        ctx: &mut C,
    ) -> SumcheckView<C> {
        assert!(self.num_variables >= 1);

        let claim = ctx.to_value(&in_claim.claimed_sum);

        let mut point = Vec::new();
        let mut univariate_poly_coeffs = Vec::new();

        // First round
        let mut uni_poly = poly.sum_as_poly_in_last_t_variables(Some(claim), 1);
        univariate_poly_coeffs.push(ctx.send_values(&uni_poly.coefficients));
        let mut alpha: C::Challenge = ctx.sample();
        point.push(alpha);
        let mut cursor = poly.fix_t_variables(alpha.into(), 1);

        // Remaining rounds
        for _ in 1..self.num_variables {
            let round_claim = uni_poly.eval_at_point(alpha.into());
            uni_poly = cursor.sum_as_poly_in_last_variable(Some(round_claim));
            univariate_poly_coeffs.push(ctx.send_values(&uni_poly.coefficients));
            alpha = ctx.sample();
            point.push(alpha);
            cursor = cursor.fix_last_variable(alpha.into());
        }

        // Point was collected outer-to-inner, reverse to match convention
        point.reverse();

        // Send the final claimed evaluation.
        // Note: this is derivable from `univariate_poly_coeffs.last()` evaluated at the
        // last alpha, so it's redundant transcript data. Kept for external compatibility.
        let eval = uni_poly.eval_at_point(alpha.into());
        let claimed_eval = ctx.send_value(eval);

        // Send component evaluations if requested
        let component_evals = if self.num_component_evals > 0 {
            let evals = cursor.get_component_poly_evals();
            assert_eq!(
                evals.len(),
                self.num_component_evals,
                "component eval count mismatch: poly has {} but param expects {}",
                evals.len(),
                self.num_component_evals,
            );
            ctx.send_values(&evals)
        } else {
            vec![]
        };

        SumcheckView {
            out_claim: SumcheckOutputClaim { point, claimed_eval, component_evals },
            univariate_poly_coeffs,
        }
    }
}

impl<C: ConstraintCtx> SumcheckView<C> {
    /// Emit all sumcheck verification constraints.
    ///
    /// Checks:
    /// 1. Round 0: `in_claim.claimed_sum == eval(0) + eval(1)` of first univariate.
    /// 2. Intermediate rounds: `poly_{i-1}(alpha_{i-1}) == eval(0) + eval(1)` of `poly_i`.
    /// 3. Final round: last poly evaluated at alpha == `out_claim.claimed_eval`.
    ///
    /// The caller is responsible for consuming `self.out_claim` downstream (either by
    /// feeding it into another protocol or by calling primitive discharge operations
    /// like `ctx.assert_mle_eval`).
    pub fn build_constraints(
        self,
        in_claim: &SumcheckInputClaim<C>,
        ctx: &mut C,
    ) -> Result<(), SumcheckError> {
        let num_variables = self.univariate_poly_coeffs.len();
        if num_variables == 0 {
            return Err(SumcheckError::EmptyProof);
        }

        // Round 0: in_claim.claimed_sum == eval(0) + eval(1) of first univariate.
        let first_round = C::eval_one_plus_eval_zero(&self.univariate_poly_coeffs[0])
            - in_claim.claimed_sum.clone();
        ctx.assert_zero(first_round);

        // Intermediate rounds: poly_{i-1}(alpha_{i-1}) == eval(0) + eval(1) of poly_i.
        for i in 1..num_variables {
            let alpha = self.out_claim.point[num_variables - i];
            let lhs = C::poly_eval(&self.univariate_poly_coeffs[i - 1], alpha);
            let rhs = C::eval_one_plus_eval_zero(&self.univariate_poly_coeffs[i]);
            ctx.assert_zero(lhs - rhs);
        }

        // Final round: last poly evaluated at alpha == claimed_eval.
        let alpha = self.out_claim.point[0];
        let final_eval = C::poly_eval(&self.univariate_poly_coeffs[num_variables - 1], alpha);
        ctx.assert_zero(final_eval - self.out_claim.claimed_eval);

        Ok(())
    }
}
