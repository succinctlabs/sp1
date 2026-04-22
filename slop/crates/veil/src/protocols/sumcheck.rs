use slop_algebra::{rlc_univariate_polynomials, AbstractField};
use slop_sumcheck::{ComponentPoly, SumcheckPoly, SumcheckPolyFirstRound};
use thiserror::Error;

use crate::compiler::{ConstraintCtx, ReadingCtx, SendingCtx, TranscriptExhaustedError};

#[derive(Debug, Error)]
pub enum SumcheckError {
    #[error("sumcheck requires at least one variable, got 0")]
    NoVariables,
    #[error("sumcheck proof has no rounds")]
    EmptyProof,
    #[error("sumcheck param expects {expected} polys but caller provided {actual}")]
    PolyCountMismatch { expected: usize, actual: usize },
    #[error("input-claim count ({claims}) does not match poly count ({polys})")]
    ClaimPolyCountMismatch { claims: usize, polys: usize },
    #[error("unexpected end of transcript")]
    TranscriptExhausted(#[from] TranscriptExhaustedError),
}

/// Parameters for a sumcheck protocol instance.
///
/// Static shape only — no field values and no context-dependent data. A
/// sumcheck can batch N independent polynomials (all of the same `num_variables`
/// and `degree`) via a random linear combination; `poly_component_counts` has
/// one entry per polynomial giving how many component evaluations that poly
/// reports at the end of the sumcheck.
pub struct SumcheckParam {
    /// Number of variables in the sumcheck.
    pub num_variables: u32,
    /// Degree of the composition polynomial (same for every batched poly).
    pub degree: usize,
    /// Number of component evaluations sent per polynomial. `len()` is the
    /// number of polynomials being batched; use length-1 for non-batched.
    pub poly_component_counts: Vec<usize>,
}

/// Input claim: "the sum of each composition polynomial over `{0,1}^n` equals
/// the corresponding `claimed_sum`."
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

/// Output claim: "the (RLC-combined) composition polynomial evaluates to
/// `claimed_eval` at random point `point`, with each component polynomial of
/// each batched poly evaluating to the corresponding entry of `component_evals`
/// at `point`."
///
/// This is the reduced claim handed off to downstream protocols (typically MLE
/// PCS openings, or another sumcheck).
pub struct SumcheckOutputClaim<C: ConstraintCtx> {
    /// Fiat-Shamir challenges (evaluation point), stored inner-to-outer.
    pub point: Vec<C::Challenge>,
    /// Claimed evaluation of the RLC-combined composition polynomial at `point`.
    pub claimed_eval: C::Expr,
    /// Per-polynomial component evaluations at `point`: outer index = poly index,
    /// inner index = component within that poly. Inner vecs have the lengths
    /// specified by `SumcheckParam::poly_component_counts`.
    pub component_evals: Vec<Vec<C::Expr>>,
}

/// Returned by `prove` / `read`. Carries the output claim plus the per-round univariate
/// polynomial coefficients needed by `build_constraints` to emit round-consistency checks.
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

    /// Multi-poly RLC-batched prove. `in_claims[i]` is the claim for poly `i`,
    /// `lambda` is the RLC coefficient; every round's univariate is the RLC of
    /// the per-poly univariates (via Horner in `lambda`). `in_claims.len()` must
    /// equal `polys.len()` must equal `self.num_polys()`.
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

        // ---- First round ----
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

        // ---- Remaining rounds ----
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
    /// Emit sumcheck round-consistency constraints for the non-batched case
    /// (one input poly, one input claim). Thin wrapper around
    /// [`Self::build_constraints_batched`].
    pub fn build_constraints(
        self,
        in_claim: &SumcheckInputClaim<C>,
        ctx: &mut C,
    ) -> Result<(), SumcheckError> {
        self.build_constraints_batched(std::slice::from_ref(in_claim), C::Challenge::one(), ctx)
    }

    /// Emit sumcheck round-consistency constraints for an RLC-batched proof.
    ///
    /// Checks:
    /// 1. Round 0: `rlc(in_claims, lambda) == eval(0) + eval(1)` of the first
    ///    (RLC'd) univariate. For a single-claim call this reduces to the usual
    ///    `claimed_sum == eval(0) + eval(1)` check.
    /// 2. Intermediate rounds: `poly_{i-1}(alpha_{i-1}) == eval(0) + eval(1)`
    ///    of the RLC'd `poly_i`.
    /// 3. Final round: last RLC'd poly evaluated at `alpha` equals
    ///    `out_claim.claimed_eval`.
    ///
    /// `lambda` is the same RLC coefficient the prover used, typed here as
    /// `C::Challenge` because the constraint is expressed via `C::poly_eval`
    /// (which takes a challenge). Callers that sampled `lambda` as an extension
    /// element on the prover side pass the identical challenge back on the
    /// verifier side.
    pub fn build_constraints_batched(
        self,
        in_claims: &[SumcheckInputClaim<C>],
        lambda: C::Challenge,
        ctx: &mut C,
    ) -> Result<(), SumcheckError> {
        let num_variables = self.univariate_poly_coeffs.len();
        if num_variables == 0 {
            return Err(SumcheckError::EmptyProof);
        }
        if in_claims.is_empty() {
            return Err(SumcheckError::ClaimPolyCountMismatch { claims: 0, polys: 1 });
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
