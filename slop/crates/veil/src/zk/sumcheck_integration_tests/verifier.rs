use crate::zk::inner::{
    ConstraintContextInnerExt, ZkCnstrAndReadingCtxInner, ZkIopCtx, ZkProtocolParameters,
    ZkProtocolProof,
};
use derive_where::derive_where;
use slop_algebra::AbstractField;

use slop_challenger::FieldChallenger;

/// Parameters for the zero-knowledge sumcheck protocol.
#[derive(Clone)]
#[derive_where(Debug; C::Expr)]
pub struct ZkPartialSumcheckParameters<GC: ZkIopCtx, C: ConstraintContextInnerExt<GC::EF>> {
    /// Number of variables in the sumcheck.
    pub num_variables: u32,
    /// Degree of the polynomials.
    pub degree: usize,
    /// Multilinear component counts for each polynomial.
    pub poly_component_counts: Vec<usize>,
    /// Indices in the proof transcript of the claimed hypercube sums of polynomials.
    pub claim_exprs: Vec<C::Expr>,
    /// RLC coefficient for the input polynomials.
    pub lambda: GC::EF,
    /// Number of rounds to skip (not supported yet).
    pub t: u32,
}

impl<GC: ZkIopCtx, C: ConstraintContextInnerExt<GC::EF>> ZkPartialSumcheckParameters<GC, C> {
    /// Parameters for a basic Hadamard product sumcheck with 2 multilinear components and degree 2.
    pub fn basic_hadamard_sumcheck(num_vars: u32, claim_expr: C::Expr) -> Self {
        ZkPartialSumcheckParameters {
            num_variables: num_vars,
            degree: 2,
            poly_component_counts: vec![2],
            claim_exprs: vec![claim_expr],
            lambda: GC::EF::one(),
            t: 1,
        }
    }

    /// Parameters for a basic multilinear sumcheck with 1 multilinear component and degree 1.
    pub fn basic_sumcheck(num_vars: u32, claim_expr: C::Expr) -> Self {
        ZkPartialSumcheckParameters {
            num_variables: num_vars,
            degree: 1,
            poly_component_counts: vec![1],
            claim_exprs: vec![claim_expr],
            lambda: GC::EF::one(),
            t: 1,
        }
    }
}

/// Self-contained proof for zk-sumcheck that includes parameters.
///
/// Contains all data needed to generate constraints without additional inputs.
/// Generic over the context type `C` which can be `ZkVerificationContext` or `ZkProverContext`.
#[derive(Clone)]
#[derive_where(Debug; C::Expr)]
pub struct ZkPartialSumcheckProof<GC: ZkIopCtx, C: ConstraintContextInnerExt<GC::EF>> {
    /// The parameters this proof was read with
    pub parameters: ZkPartialSumcheckParameters<GC, C>,
    /// Univariate polynomial coefficients for each round
    pub univariate_poly_coeffs: Vec<Vec<C::Expr>>,
    /// Claimed sum of the polynomial
    pub claimed_sum: C::Expr,
    /// Evaluation point (Fiat-Shamir challenges)
    pub point: Vec<GC::EF>,
    /// Claimed evaluation at the point
    pub claimed_eval: C::Expr,
    /// Component polynomial evaluations
    pub component_poly_evals: Vec<Vec<C::Expr>>,
}

impl<GC: ZkIopCtx, C: ZkCnstrAndReadingCtxInner<GC>> ZkProtocolParameters<GC, C>
    for ZkPartialSumcheckParameters<GC, C>
{
    type Proof = ZkPartialSumcheckProof<GC, C>;

    fn read_proof_from_transcript(&self, context: &mut C) -> Option<Self::Proof> {
        // Proof shape checks
        if self.num_variables == 0 {
            return None;
        }
        if self.poly_component_counts.len() != self.claim_exprs.len() {
            return None;
        }

        let mut alpha_point: Vec<GC::EF> = vec![];
        let mut univariate_poly_coeffs = vec![];

        // Read in univariate polynomials from the proof values and sample alphas
        for _ in 0..self.num_variables {
            let coeffs = context.read_next(self.degree + 1)?;

            let alpha = context.challenger().sample_ext_element();
            alpha_point.insert(0, alpha);

            univariate_poly_coeffs.push(coeffs);
        }

        // Read in claimed sum and claimed eval
        let claimed_sum = context.read_one()?;
        let claimed_eval = context.read_one()?;

        // Read in and observe component polys
        let mut component_poly_evals = vec![];
        for count in self.poly_component_counts.iter() {
            let eval = context.read_next(*count)?;
            component_poly_evals.push(eval);
        }

        Some(ZkPartialSumcheckProof {
            parameters: self.clone(),
            univariate_poly_coeffs,
            claimed_sum,
            point: alpha_point,
            claimed_eval,
            component_poly_evals,
        })
    }
}

impl<GC: ZkIopCtx, C: ConstraintContextInnerExt<GC::EF>> ZkProtocolProof<GC, C>
    for ZkPartialSumcheckProof<GC, C>
{
    fn build_constraints(self) {
        let params = self.parameters;
        let mut context = self.claimed_sum.as_ref().clone();

        // Check that the first polynomial is consistent with the claimed sum
        // claimed_sum - eval_one_plus_eval_zero(poly[0]) = 0
        let first_round_constraint =
            C::eval_one_plus_eval_zero(&self.univariate_poly_coeffs[0]) - self.claimed_sum.clone();
        context.assert_zero(first_round_constraint);

        // Check the intermediate sumcheck round consistencies
        for i in 1..params.num_variables {
            let alpha = self.point[(params.num_variables - i) as usize];
            let intermediate_round_constraint =
                C::poly_eval(&self.univariate_poly_coeffs[(i - 1) as usize], alpha)
                    - C::eval_one_plus_eval_zero(&self.univariate_poly_coeffs[i as usize]);
            context.assert_zero(intermediate_round_constraint);
        }

        // Check that the evaluation claim implied by the last univariate polynomial matches the
        // given evaluation claim
        let alpha = self.point[0];
        let eval_claim_constraint =
            C::poly_eval(&self.univariate_poly_coeffs[(params.num_variables - 1) as usize], alpha)
                - self.claimed_eval;
        context.assert_zero(eval_claim_constraint);

        // Check that the individual poly evaluations were RLC'ed correctly.
        // The prover uses Horner left-to-right: claims[0]*lambda^(n-1) + ... + claims[n-1],
        // so we reverse the claims before poly_eval (which treats index 0 as the constant term).
        let mut reversed_claims = params.claim_exprs;
        reversed_claims.reverse();
        let rlc_constraint = C::poly_eval(&reversed_claims, params.lambda) - self.claimed_sum;
        context.assert_zero(rlc_constraint);
    }
}
