use slop_sumcheck::{SumcheckPoly, SumcheckPolyFirstRound};
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
pub struct SumcheckParam {
    /// Number of variables in the sumcheck.
    pub num_variables: u32,
    /// Degree of the composition polynomial.
    pub degree: usize,
}

/// All proof data read from the transcript for a sumcheck instance.
///
/// Pure sumcheck verification: checks round consistency and produces a claimed evaluation at a
/// random point. The caller is responsible for verifying that the claimed evaluation is correct
/// (e.g., by opening committed polynomials).
pub struct SumcheckView<C: ConstraintCtx> {
    /// Univariate polynomial coefficients for each round.
    pub univariate_poly_coeffs: Vec<Vec<C::Expr>>,
    /// Fiat-Shamir challenges (evaluation point), stored inner-to-outer.
    pub point: Vec<C::Challenge>,
    /// Claimed sum of the polynomial over the hypercube.
    pub claimed_sum: C::Expr,
    /// Claimed evaluation at the random point (output of the sumcheck).
    pub claimed_eval: C::Expr,
}

impl SumcheckParam {
    pub fn new(num_variables: u32, degree: usize) -> Self {
        Self { num_variables, degree }
    }

    /// Read the sumcheck proof from the transcript.
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

        let claimed_sum = ctx.read_one()?;
        let claimed_eval = ctx.read_one()?;

        Ok(SumcheckView { univariate_poly_coeffs, point: alphas, claimed_sum, claimed_eval })
    }

    /// Run the prover side of sumcheck, sending messages through the context.
    ///
    /// Returns a `SumcheckView` that can be used to build verification constraints.
    pub fn prove<C: SendingCtx>(
        &self,
        poly: impl SumcheckPolyFirstRound<C::Extension>,
        ctx: &mut C,
        claim: C::Extension,
    ) -> SumcheckView<C> {
        assert!(self.num_variables >= 1);

        let mut point = Vec::new();
        let mut univariate_poly_coeffs = Vec::new();

        // First round
        let mut uni_poly = poly.sum_as_poly_in_last_t_variables(Some(claim), 1);
        univariate_poly_coeffs.push(ctx.send_values(&uni_poly.coefficients));
        let mut alpha: C::Challenge = ctx.sample();
        point.push(alpha.clone());
        let mut cursor = poly.fix_t_variables(alpha.clone().into(), 1);

        // Remaining rounds
        for _ in 1..self.num_variables {
            let round_claim = uni_poly.eval_at_point(alpha.clone().into());
            uni_poly = cursor.sum_as_poly_in_last_variable(Some(round_claim));
            univariate_poly_coeffs.push(ctx.send_values(&uni_poly.coefficients));
            alpha = ctx.sample();
            point.push(alpha.clone());
            cursor = cursor.fix_last_variable(alpha.clone().into());
        }

        // Point was collected outer-to-inner, reverse to match convention
        point.reverse();

        // Send claimed sum and claimed eval
        let claimed_sum = ctx.send_value(claim);
        let eval = uni_poly.eval_at_point(alpha.into());
        let claimed_eval = ctx.send_value(eval);

        SumcheckView { univariate_poly_coeffs, point, claimed_sum, claimed_eval }
    }
}

impl<C: ConstraintCtx> SumcheckView<C> {
    /// Emit all sumcheck verification constraints.
    ///
    /// Checks:
    /// 1. Round 0: claimed_sum == eval(0) + eval(1) of first univariate
    /// 2. Intermediate rounds: poly_{i-1}(alpha_{i-1}) == eval(0) + eval(1) of poly_i
    /// 3. Final round: last poly evaluated at alpha == claimed_eval
    ///
    /// After this, the caller should verify that `claimed_eval` matches the actual polynomial
    /// evaluation at `point`.
    pub fn build_constraints(self, ctx: &mut C) -> Result<(), SumcheckError> {
        let num_variables = self.univariate_poly_coeffs.len();
        if num_variables == 0 {
            return Err(SumcheckError::EmptyProof);
        }

        // Round 0: claimed_sum == eval(0) + eval(1) of first univariate.
        let first_round =
            C::eval_one_plus_eval_zero(&self.univariate_poly_coeffs[0]) - self.claimed_sum.clone();
        ctx.assert_zero(first_round);

        // Intermediate rounds: poly_{i-1}(alpha_{i-1}) == eval(0) + eval(1) of poly_i.
        for i in 1..num_variables {
            let alpha = self.point[num_variables - i].clone();
            let lhs = C::poly_eval(&self.univariate_poly_coeffs[i - 1], alpha);
            let rhs = C::eval_one_plus_eval_zero(&self.univariate_poly_coeffs[i]);
            ctx.assert_zero(lhs - rhs);
        }

        // Final round: last poly evaluated at alpha == claimed_eval.
        let alpha = self.point[0].clone();
        let final_eval = C::poly_eval(&self.univariate_poly_coeffs[num_variables - 1], alpha);
        ctx.assert_zero(final_eval - self.claimed_eval);

        Ok(())
    }
}
