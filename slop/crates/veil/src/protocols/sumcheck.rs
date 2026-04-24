use slop_algebra::{rlc_univariate_polynomials, AbstractField};
use slop_sumcheck::{ComponentPoly, SumcheckPoly, SumcheckPolyFirstRound};
use thiserror::Error;

use crate::compiler::{ConstraintCtx, ReadingCtx, SendingCtx, TranscriptReadError};

/// Sumcheck verification errors, shaped to mirror
/// [`slop_sumcheck::verifier::SumcheckError`]. The specific round-failure
/// variants only surface in eager-checking backends (transparent); deferred
/// backends (ZK) accumulate the failure into a flag surfaced at `ctx.verify()`.
#[derive(Debug, Error)]
pub enum SumcheckError {
    #[error("invalid proof shape")]
    InvalidProofShape,
    #[error("sumcheck round inconsistency")]
    SumcheckRoundInconsistency,
    #[error("inconsistency of prover message with claimed sum")]
    InconsistencyWithClaimedSum,
    #[error("inconsistency of proof with evaluation claim")]
    InconsistencyWithEval,
    #[error("unexpected end of transcript")]
    TranscriptExhausted(#[from] TranscriptReadError),
}

/// Static shape of a sumcheck instance. `poly_component_counts.len()` is the
/// number of polynomials being RLC-batched (1 for non-batched); each entry is
/// how many component evaluations that poly reports at the end.
pub struct SumcheckParam {
    /// Number of variables in the sumcheck.
    pub num_variables: u32,
    /// Degree of the composition polynomial (same for every batched poly).
    pub degree: usize,
    /// Number of component evaluations sent per polynomial. `len()` is the
    /// number of polynomials being batched; use length-1 for non-batched.
    pub poly_component_counts: Vec<usize>,
}

/// "The sum of the composition polynomial over `{0,1}^n` equals `claimed_sum`."
/// Not transmitted on the transcript; supplied by the caller to `build_constraints`
/// as a public constant or an upstream protocol's output claim.
#[derive(Clone)]
pub struct SumcheckInputClaim<C: ConstraintCtx> {
    pub claimed_sum: C::Expr,
}

impl<C: ConstraintCtx> SumcheckInputClaim<C> {
    /// Claim that the hypercube sum is zero (zerocheck).
    pub fn zero() -> Self {
        Self { claimed_sum: C::Expr::zero() }
    }

    /// Claim from a concrete extension-field value, lifted to an `Expr`.
    pub fn from_value(value: C::Extension) -> Self {
        Self { claimed_sum: C::Expr::one() * value }
    }
}

/// Reduced claim output by the sumcheck, handed to downstream protocols (PCS
/// openings, another sumcheck): the RLC-combined composition poly evaluates to
/// `claimed_eval` at `point`, with per-poly components as in `component_evals`.
pub struct SumcheckOutputClaim<C: ConstraintCtx> {
    /// Fiat-Shamir challenges (evaluation point), stored inner-to-outer.
    pub point: Vec<C::Challenge>,
    /// Evaluation of the RLC-combined composition poly at `point`.
    pub claimed_eval: C::Expr,
    /// Per-poly component evals: `component_evals[i][j]` = component `j` of
    /// batched poly `i`, with inner lengths from `poly_component_counts`.
    pub component_evals: Vec<Vec<C::Expr>>,
}

/// Returned by `prove` / `read`. The output claim plus the per-round univariate
/// coefficients `build_constraints` needs.
pub struct SumcheckView<C: ConstraintCtx> {
    pub out_claim: SumcheckOutputClaim<C>,
    pub(crate) univariate_poly_coeffs: Vec<Vec<C::Expr>>,
}

impl SumcheckParam {
    /// Single-poly sumcheck with no component evaluations.
    pub fn new(num_variables: u32, degree: usize) -> Self {
        Self { num_variables, degree, poly_component_counts: vec![0] }
    }

    /// Single-poly sumcheck that also sends the given number of component evaluations.
    pub fn with_component_evals(
        num_variables: u32,
        degree: usize,
        num_component_evals: usize,
    ) -> Self {
        Self { num_variables, degree, poly_component_counts: vec![num_component_evals] }
    }

    /// Multi-poly sumcheck batched by RLC. `poly_component_counts.len()` is the
    /// number of polynomials; each entry is that poly's component-eval count.
    pub fn with_poly_component_counts(
        num_variables: u32,
        degree: usize,
        poly_component_counts: Vec<usize>,
    ) -> Self {
        Self { num_variables, degree, poly_component_counts }
    }

    /// Number of polynomials this sumcheck batches. `1` for non-batched.
    pub fn num_polys(&self) -> usize {
        self.poly_component_counts.len()
    }

    /// Read the sumcheck proof from the transcript. The input claim is passed
    /// separately to `build_constraints`, not read from the transcript.
    pub fn read<C: ReadingCtx>(&self, ctx: &mut C) -> Result<SumcheckView<C>, SumcheckError> {
        if self.num_variables == 0 {
            return Err(SumcheckError::InvalidProofShape);
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

        let mut component_evals = Vec::with_capacity(self.poly_component_counts.len());
        for &count in &self.poly_component_counts {
            component_evals.push(if count > 0 { ctx.read_next(count)? } else { vec![] });
        }

        Ok(SumcheckView {
            out_claim: SumcheckOutputClaim { point: alphas, claimed_eval, component_evals },
            univariate_poly_coeffs,
        })
    }

    /// Single-poly prove: thin wrapper around [`Self::prove_batched`] with a
    /// single-claim input and `lambda = 1`.
    pub fn prove<C: SendingCtx>(
        &self,
        in_claim: &SumcheckInputClaim<C>,
        poly: impl SumcheckPolyFirstRound<C::Extension>,
        ctx: &mut C,
    ) -> SumcheckView<C> {
        assert_eq!(
            self.num_polys(),
            1,
            "single-poly `prove` requires exactly one poly_component_count entry; use `prove_batched` for multi-poly",
        );
        self.prove_batched(std::slice::from_ref(in_claim), C::Extension::one(), vec![poly], ctx)
    }

    /// Multi-poly RLC-batched prove. Each round emits the Horner-in-`lambda`
    /// RLC of the per-poly univariates. `in_claims.len() == polys.len() ==
    /// self.num_polys()`.
    pub fn prove_batched<C: SendingCtx>(
        &self,
        in_claims: &[SumcheckInputClaim<C>],
        lambda: C::Extension,
        polys: Vec<impl SumcheckPolyFirstRound<C::Extension>>,
        ctx: &mut C,
    ) -> SumcheckView<C> {
        assert!(self.num_variables >= 1);
        assert_eq!(
            in_claims.len(),
            polys.len(),
            "in_claims and polys must have the same length (got {} vs {})",
            in_claims.len(),
            polys.len(),
        );
        assert_eq!(
            polys.len(),
            self.num_polys(),
            "param expects {} polys but caller supplied {}",
            self.num_polys(),
            polys.len(),
        );

        let claim_values: Vec<C::Extension> =
            in_claims.iter().map(|c| ctx.to_value(&c.claimed_sum)).collect();

        let mut point = Vec::new();
        let mut univariate_poly_coeffs = Vec::new();

        // First round.
        let mut per_poly_unis: Vec<_> = polys
            .iter()
            .zip(claim_values.iter())
            .map(|(poly, claim)| poly.sum_as_poly_in_last_t_variables(Some(*claim), 1))
            .collect();
        let mut rlc_uni = rlc_univariate_polynomials(&per_poly_unis, lambda);
        univariate_poly_coeffs.push(ctx.send_values(&rlc_uni.coefficients));
        let mut alpha: C::Challenge = ctx.sample();
        point.push(alpha);
        let mut cursors: Vec<_> =
            polys.into_iter().map(|poly| poly.fix_t_variables(alpha.into(), 1)).collect();

        // Remaining rounds.
        for _ in 1..self.num_variables {
            let round_claims: Vec<_> =
                per_poly_unis.iter().map(|u| u.eval_at_point(alpha.into())).collect();
            per_poly_unis = cursors
                .iter()
                .zip(round_claims)
                .map(|(cur, rc)| cur.sum_as_poly_in_last_variable(Some(rc)))
                .collect();
            rlc_uni = rlc_univariate_polynomials(&per_poly_unis, lambda);
            univariate_poly_coeffs.push(ctx.send_values(&rlc_uni.coefficients));
            alpha = ctx.sample();
            point.push(alpha);
            cursors = cursors.into_iter().map(|cur| cur.fix_last_variable(alpha.into())).collect();
        }

        // Point was collected outer-to-inner, reverse to match convention
        point.reverse();

        // Send the final claimed evaluation (RLC of per-poly final evals, also
        // reproducible from `univariate_poly_coeffs.last()` at `alpha`).
        let eval = rlc_uni.eval_at_point(alpha.into());
        let claimed_eval = ctx.send_value(eval);

        // Send per-poly component evaluations (nested in the view).
        let mut component_evals = Vec::with_capacity(self.poly_component_counts.len());
        for (cursor, &expected_count) in cursors.iter().zip(&self.poly_component_counts) {
            if expected_count > 0 {
                let evals = cursor.get_component_poly_evals();
                assert_eq!(
                    evals.len(),
                    expected_count,
                    "component eval count mismatch: poly reported {} but param expects {}",
                    evals.len(),
                    expected_count,
                );
                component_evals.push(ctx.send_values(&evals));
            } else {
                component_evals.push(vec![]);
            }
        }

        SumcheckView {
            out_claim: SumcheckOutputClaim { point, claimed_eval, component_evals },
            univariate_poly_coeffs,
        }
    }
}

impl<C: ConstraintCtx> SumcheckView<C> {
    /// Non-batched round-consistency constraints. Thin wrapper around
    /// [`Self::build_constraints_batched`] with one claim and `lambda = 1`.
    pub fn build_constraints(
        self,
        in_claim: &SumcheckInputClaim<C>,
        ctx: &mut C,
    ) -> Result<(), SumcheckError> {
        self.build_constraints_batched(std::slice::from_ref(in_claim), C::Challenge::one(), ctx)
    }

    /// Emit RLC-batched round-consistency constraints: round 0 ties
    /// `rlc(in_claims, lambda)` to the first univariate, intermediates chain
    /// via `poly_{i-1}(alpha_{i-1}) == eval(0) + eval(1)` of `poly_i`, and the
    /// final round ties the last univariate at `alpha` to `claimed_eval`.
    /// `lambda` is the same RLC coefficient the prover used.
    pub fn build_constraints_batched(
        self,
        in_claims: &[SumcheckInputClaim<C>],
        lambda: C::Challenge,
        ctx: &mut C,
    ) -> Result<(), SumcheckError> {
        let num_variables = self.univariate_poly_coeffs.len();
        if num_variables == 0 || in_claims.is_empty() {
            return Err(SumcheckError::InvalidProofShape);
        }

        // Round 0: rlc(in_claims, lambda) == eval(0) + eval(1) of first univariate.
        //
        // Expression-level Horner: claims[0] * lambda^(N-1) + ... + claims[N-1].
        // We reuse `C::poly_eval`, which computes `c_0 + c_1*x + ... + c_{n-1}*x^{n-1}`,
        // so feeding the reversed claims to it yields the desired Horner form.
        let reversed_claims: Vec<C::Expr> =
            in_claims.iter().rev().map(|c| c.claimed_sum.clone()).collect();
        let rlc_claim = C::poly_eval(&reversed_claims, lambda);
        let first_round = C::eval_one_plus_eval_zero(&self.univariate_poly_coeffs[0]) - rlc_claim;
        ctx.assert_zero(first_round).map_err(|_| SumcheckError::InconsistencyWithClaimedSum)?;

        // Intermediate rounds: poly_{i-1}(alpha_{i-1}) == eval(0) + eval(1) of poly_i.
        for i in 1..num_variables {
            let alpha = self.out_claim.point[num_variables - i];
            let lhs = C::poly_eval(&self.univariate_poly_coeffs[i - 1], alpha);
            let rhs = C::eval_one_plus_eval_zero(&self.univariate_poly_coeffs[i]);
            ctx.assert_zero(lhs - rhs).map_err(|_| SumcheckError::SumcheckRoundInconsistency)?;
        }

        // Final round: last poly evaluated at alpha == claimed_eval.
        let alpha = self.out_claim.point[0];
        let final_eval = C::poly_eval(&self.univariate_poly_coeffs[num_variables - 1], alpha);
        ctx.assert_zero(final_eval - self.out_claim.claimed_eval)
            .map_err(|_| SumcheckError::InconsistencyWithEval)?;

        Ok(())
    }
}
