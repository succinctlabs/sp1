//! CPU prover for the two-stage-GKR Option 2 shape.
//!
//! Given K = K_1 · K_2 base-field MLEs `p_k` over c variables, ζ ∈ EF^c, and z ∈ EF^K, the
//! original sum we want to prove is
//!
//!   ∑_{i ∈ {0,1}^c} eq(ζ, i) · ∏_{k=1..K} eq(z_k, p_k[i]).
//!
//! We split the degree-K product across two lower-degree sumchecks:
//!
//! * **Stage 1** (degree K_2 + 1): define K_2 ext-field outer MLEs
//!   B_j[i] = ∏_{j' = 1..K_1} eq(z_{jK_1 + j'}, p_{jK_1 + j'}[i]),
//!   and run the eq-prefixed sumcheck `∑_i eq(ζ, i) · ∏_j B_j[i]`.  This reduces to claims
//!   B_j(ζ'') = v_j sent in the clear.
//! * **Stage 2** (degree K_1 + 1): the verifier samples ζ''' ∈ EF^{log K_2}, computes
//!   w_j = eq(ζ''', j), and accepts the new claim ∑_j w_j · v_j.  Then both sides run a
//!   sumcheck on
//!   ∑_{i ∈ {0,1}^c} eq(ζ'', i) · ∑_{j=1..K_2} w_j · ∏_{j' = 1..K_1} eq(z_{jK_1 + j'},
//!   p_{jK_1 + j'}[i]).
//!   The inner K_2 sum is small (≤ 64) and stays inside the verifier's loop — it is *not*
//!   sumchecked over.  After the round-by-round fold we end with one evaluation claim on
//!   ∑_j w_j · ∏_{j'} eq(z_{jK_1 + j'}, p_{jK_1 + j'}(η)),
//!   which is verified by sending the K base-field evaluations `p_k(η)` (a PCS opening of
//!   the committed `p_k`'s) and recomputing the expression.
//!
//! Stage 1 reuses [`crate::eq_product_prover::EqProductPoly`] with z_stage1 = `[1, …, 1]`
//! so that its `(a_j, b_j) = (0, 1)` collapse the eq-factor to the plain B_j factor — no
//! new polynomial type needed.  Stage 2 needs a new type [`EqOuterSumPoly`] because the
//! round univariate is the K_2-loop ∑_j w_j · (K_1 product) rather than a single K-factor
//! product.

use rayon::prelude::*;
use slop_algebra::{
    AbstractExtensionField, AbstractField, ExtensionField, Field, UnivariatePolynomial,
};
use slop_alloc::{CpuBackend, HasBackend};
use slop_challenger::FieldChallenger;
use slop_multilinear::{partial_lagrange, Mle, Point};
use slop_sumcheck::{
    reduce_sumcheck_to_evaluation, ComponentPolyEvalBackend, SumCheckPolyFirstRoundBackend,
    SumcheckPolyBackend, SumcheckPolyBase,
};
use slop_tensor::Tensor;

use crate::eq_product_prover::{sum_pair_eq_prefix_scaled, EqProductPoly};
use crate::two_stage_eq_product_verifier::TwoStageEqProductProof;

/// Stage-2 polynomial state: degree-(K_1 + 1) sumcheck with an outer K_2 weighted sum.
///
/// In round 0 the K = K_1 · K_2 inner factors are base-field MLEs (`F` = base, `EF` = ext);
/// after the first fold both the MLE and the eq prefix are in EF, so the next-round struct
/// is `EqOuterSumPoly<EF, EF>`.
#[derive(Clone, Debug)]
pub struct EqOuterSumPoly<F, EF = F> {
    /// K-batched MLE of the K = K_1 · K_2 inner factors, row-major (each row is one i ∈
    /// {0,1}^c with K consecutive p_k[i] values).
    pub mle: Mle<F, CpuBackend>,
    /// Eq prefix tensor E_r over the c − r remaining non-eval variables (size 2^(c − r) in
    /// round r).  Folds across the j-loop because eq(ζ'', i) factors out of the inner sum.
    pub eq_prefix: Mle<EF, CpuBackend>,
    /// `a[k] = 1 − z_k`.  Precomputed once at construction (length K).
    pub a: Vec<EF>,
    /// `b[k] = 2 z_k − 1`.  Precomputed once at construction (length K).
    pub b: Vec<EF>,
    /// `w[j] = eq(ζ''', j)` for j ∈ 0..K_2.  Constant across all rounds; mixed into the
    /// j' = 0 factor of each j-group during sum-as-poly.
    pub w: Vec<EF>,
    /// Inner product width K_1.
    pub k1: usize,
    /// Outer sum width K_2 (= K / K_1).
    pub k2: usize,
    /// Remaining ζ''-coordinates [ζ''_1, …, ζ''_remaining]; `last()` is the ζ-coordinate for
    /// the round currently being run (the one we pull out via the Gruen factor).
    pub remaining_zetas: Vec<EF>,
}

impl<F, EF> EqOuterSumPoly<F, EF>
where
    F: AbstractField,
    EF: AbstractExtensionField<F> + 'static,
{
    /// Build an [EqOuterSumPoly] from the K-batched base MLE, ζ'' (c elements), z (K
    /// elements), w (K_2 elements), and the (K_1, K_2) split.
    pub fn new(
        mle: Mle<F, CpuBackend>,
        zeta: Vec<EF>,
        z: Vec<EF>,
        w: Vec<EF>,
        k1: usize,
        k2: usize,
    ) -> Self {
        let k = mle.num_polynomials();
        let n = mle.num_variables() as usize;
        assert_eq!(k, k1 * k2, "K_1 · K_2 must equal the MLE's polynomial count");
        assert_eq!(zeta.len(), n, "zeta must have one ext element per MLE variable");
        assert_eq!(z.len(), k, "z must have one ext element per inner factor");
        assert_eq!(w.len(), k2, "w must have one weight per outer index j");
        assert!(n >= 1, "need at least one variable");

        let a: Vec<EF> = z.iter().map(|zk| EF::one() - zk.clone()).collect();
        let b: Vec<EF> = z.iter().map(|zk| zk.clone() + zk.clone() - EF::one()).collect();

        // Initial eq prefix E_1 over ζ''_1..ζ''_{c−1}: partial Lagrange tensor of size 2^(c−1).
        let zeta_prefix: Point<EF, CpuBackend> = zeta[..n - 1].to_vec().into();
        let eq_prefix_tensor = partial_lagrange(&zeta_prefix);
        let eq_prefix = Mle::new(eq_prefix_tensor);

        Self { mle, eq_prefix, a, b, w, k1, k2, remaining_zetas: zeta }
    }
}

impl<F, EF> HasBackend for EqOuterSumPoly<F, EF>
where
    F: AbstractField,
    EF: AbstractExtensionField<F>,
{
    type Backend = CpuBackend;
    fn backend(&self) -> &Self::Backend {
        self.mle.backend()
    }
}

impl<F, EF> SumcheckPolyBase for EqOuterSumPoly<F, EF>
where
    F: AbstractField,
    EF: AbstractExtensionField<F>,
{
    fn num_variables(&self) -> u32 {
        self.mle.num_variables()
    }
}

impl<F, EF> ComponentPolyEvalBackend<EqOuterSumPoly<F, EF>, EF> for CpuBackend
where
    F: Field,
    EF: ExtensionField<F>,
{
    fn get_component_poly_evals(poly: &EqOuterSumPoly<F, EF>) -> Vec<EF> {
        // After every variable has been folded the K-batched MLE has a single hypercube
        // point — the K final per-factor evaluation claims sit in the first K entries.
        let k = poly.mle.num_polynomials();
        poly.mle.guts().as_slice()[..k].iter().map(|v| EF::from_base(*v)).collect()
    }
}

// Rounds 2..c — both factor MLE and eq prefix are in EF.
impl<EF> SumcheckPolyBackend<EqOuterSumPoly<EF, EF>, EF> for CpuBackend
where
    EF: Field + 'static,
{
    fn fix_last_variable(poly: EqOuterSumPoly<EF, EF>, alpha: EF) -> EqOuterSumPoly<EF, EF> {
        fix_one_variable_outer(poly, alpha)
    }

    fn sum_as_poly_in_last_variable(
        poly: &EqOuterSumPoly<EF, EF>,
        claim: Option<EF>,
    ) -> UnivariatePolynomial<EF> {
        compute_round_univariate_outer_sum::<EF, EF>(
            poly,
            *poly.remaining_zetas.last().expect("remaining_zetas should not be empty"),
            claim.expect("expected a claim"),
        )
    }
}

// Round 1 (first round): K-batched MLE is base-field, transition to ext-field for round 2+.
impl<F, EF> SumCheckPolyFirstRoundBackend<EqOuterSumPoly<F, EF>, EF> for CpuBackend
where
    F: Field + 'static,
    EF: ExtensionField<F>,
{
    type NextRoundPoly = EqOuterSumPoly<EF, EF>;

    fn fix_t_variables(poly: EqOuterSumPoly<F, EF>, alpha: EF, t: usize) -> EqOuterSumPoly<EF, EF> {
        assert_eq!(t, 1, "EqOuterSumPoly only supports single-variable rounds");
        fix_one_variable_outer(poly, alpha)
    }

    fn sum_as_poly_in_last_t_variables(
        poly: &EqOuterSumPoly<F, EF>,
        claim: Option<EF>,
        t: usize,
    ) -> UnivariatePolynomial<EF> {
        assert_eq!(t, 1, "EqOuterSumPoly only supports single-variable rounds");
        compute_round_univariate_outer_sum::<F, EF>(
            poly,
            *poly.remaining_zetas.last().expect("remaining_zetas should not be empty"),
            claim.expect("expected a claim"),
        )
    }
}

/// Fold the last variable of the K-batched MLE by `alpha` and transition the eq prefix to
/// its next-round form (sum adjacent pairs scaled by eq(ζ_r, α_r)).  Mirrors the eq-prefix
/// transition in [`crate::eq_product_prover`] — see that module for the C_r-absorption
/// rationale.
fn fix_one_variable_outer<F, EF>(poly: EqOuterSumPoly<F, EF>, alpha: EF) -> EqOuterSumPoly<EF, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    let new_mle: Mle<EF, CpuBackend> = poly.mle.fix_last_variable::<EF>(alpha);
    let zeta_r = *poly.remaining_zetas.last().expect("remaining_zetas should not be empty");
    let eq_zr_alpha = (EF::one() - zeta_r) * (EF::one() - alpha) + zeta_r * alpha;
    let new_eq = sum_pair_eq_prefix_scaled(&poly.eq_prefix, eq_zr_alpha);
    let mut new_zetas = poly.remaining_zetas;
    new_zetas.pop();
    EqOuterSumPoly {
        mle: new_mle,
        eq_prefix: new_eq,
        a: poly.a,
        b: poly.b,
        w: poly.w,
        k1: poly.k1,
        k2: poly.k2,
        remaining_zetas: new_zetas,
    }
}

/// Build this round's univariate prover message g_r(t) = eq(ζ_r, t) · h_r(t), where
///
///   h_r(t) = ∑_{y ∈ {0,1}^{c−r}} E_r(y) · ∑_{j=1..K_2} w_j · ∏_{j'=1..K_1}
///            (a_{jK_1 + j'} + b_{jK_1 + j'} · p_{jK_1 + j'}(y, t)).
///
/// h_r is evaluated at K_1 kernel eval points (t = 0, 2, 3, …, K_1); h_r(1) is recovered
/// from the round claim via the standard Gruen relation; the cached F-typed (K_1 + 1)²
/// Lagrange matrix turns K_1 + 1 evals into power-form coefficients; a final linear
/// poly-mul by eq(ζ_r, t) lifts the degree from K_1 to K_1 + 1.
fn compute_round_univariate_outer_sum<F, EF>(
    poly: &EqOuterSumPoly<F, EF>,
    zeta_r: EF,
    claim: EF,
) -> UnivariatePolynomial<EF>
where
    F: Field + 'static,
    EF: ExtensionField<F>,
{
    let EqOuterSumPoly { mle, eq_prefix, a, b, w, k1, k2, .. } = poly;
    let (k1, k2) = (*k1, *k2);
    let k = mle.num_polynomials();
    assert_eq!(k, k1 * k2);
    assert_eq!(a.len(), k);
    assert_eq!(b.len(), k);
    assert_eq!(w.len(), k2);
    let num_vars = mle.num_variables();
    assert!(num_vars > 0, "cannot sum-as-poly a 0-variable MLE");
    let n_half = 1usize << (num_vars - 1);
    assert_eq!(eq_prefix.num_non_zero_entries(), n_half, "eq prefix must have size 2^(n−1)");

    let mle_slice = mle.guts().as_slice();
    let eq_slice = eq_prefix.guts().as_slice();

    // Step 1: kernel evals of h_r at t ∈ {0, 2, 3, …, K_1}.
    //
    // Per-thread scratch (reused across iterations to avoid per-y allocs under rayon's
    // fold driver):
    //   prod_eval : K_1 running per-j K_1-factor product at K_1 eval points
    //   per_y     : K_1 accumulator over the K_2 j-loop, scaled by eq_prefix at end-of-y
    //   acc       : K_1 thread-local accumulator over the y-loop
    let h_evals: Vec<EF> = (0..n_half)
        .into_par_iter()
        .fold(
            || (vec![EF::zero(); k1], vec![EF::zero(); k1], vec![EF::zero(); k1]),
            |(mut prod_eval, mut per_y, mut acc), x| {
                let lo_base = 2 * x * k;
                let hi_base = lo_base + k;
                let lo_chunk = &mle_slice[lo_base..lo_base + k];
                let hi_chunk = &mle_slice[hi_base..hi_base + k];
                let eq_val = eq_slice[x];

                for slot in per_y.iter_mut() {
                    *slot = EF::zero();
                }

                for (j, &wj) in w.iter().enumerate().take(k2) {
                    let base = j * k1;

                    // j' = 0: form (u, v) and absorb w[j] so it propagates through the
                    // K_1 running product for free.
                    let p_lo = lo_chunk[base];
                    let d = hi_chunk[base] - p_lo;
                    let u = a[base] + b[base] * p_lo;
                    let v = b[base] * d;
                    let u_w = wj * u;
                    let v_w = wj * v;
                    prod_eval[0] = u_w;
                    let mut cur = u_w + v_w; // skipped t = 1
                    for slot in prod_eval.iter_mut().skip(1) {
                        cur += v_w;
                        *slot = cur;
                    }

                    // j' = 1..K_1: multiply each running factor in.
                    for jp in 1..k1 {
                        let kk = base + jp;
                        let p_lo = lo_chunk[kk];
                        let d = hi_chunk[kk] - p_lo;
                        let u = a[kk] + b[kk] * p_lo;
                        let v = b[kk] * d;
                        prod_eval[0] *= u;
                        let mut cur = u + v;
                        for slot in prod_eval.iter_mut().skip(1) {
                            cur += v;
                            *slot *= cur;
                        }
                    }

                    for e in 0..k1 {
                        per_y[e] += prod_eval[e];
                    }
                }

                // Apply the eq prefix once per y (K_1 ext-mults, vs K_1 · K_2 if folded in
                // per j).
                for e in 0..k1 {
                    acc[e] += eq_val * per_y[e];
                }

                (prod_eval, per_y, acc)
            },
        )
        .map(|(_, _, acc)| acc)
        .reduce(
            || vec![EF::zero(); k1],
            |mut a, b| {
                for e in 0..k1 {
                    a[e] += b[e];
                }
                a
            },
        );

    // Step 2: recover h_r(1) from the round claim.
    //   claim = g_r(0) + g_r(1) = (1 − ζ_r) h_r(0) + ζ_r h_r(1)
    let one_minus_zeta = EF::one() - zeta_r;
    let h_at_0 = h_evals[0];
    let h_at_1 = (claim - one_minus_zeta * h_at_0) * zeta_r.inverse();

    // Step 3: assemble the K_1 + 1 y-values at nodes {0, 1, 2, …, K_1}.
    let n = k1 + 1;
    let mut y: Vec<EF> = Vec::with_capacity(n);
    y.push(h_at_0);
    y.push(h_at_1);
    y.extend_from_slice(&h_evals[1..]);

    // Step 4: cached (K_1 + 1)² Lagrange-to-power matrix → h_r's power-form coefficients.
    let m = crate::lagrange_matrix::<F>(k1);
    let mut h_coefs: Vec<EF> = Vec::with_capacity(n);
    for j in 0..n {
        let row_start = j * n;
        let mut sum = EF::zero();
        for i in 0..n {
            sum += y[i] * m[row_start + i];
        }
        h_coefs.push(sum);
    }

    // Step 5: multiply h_r(t) by eq(ζ_r, t) = (1 − ζ_r) + (2 ζ_r − 1) · t to get g_r(t).
    let two_zeta_minus_one = zeta_r + zeta_r - EF::one();
    let mut g_coefs: Vec<EF> = vec![EF::zero(); n + 1];
    for j in 0..n {
        g_coefs[j] += one_minus_zeta * h_coefs[j];
        g_coefs[j + 1] += two_zeta_minus_one * h_coefs[j];
    }

    UnivariatePolynomial::new(g_coefs)
}

/// Build the K_2 outer multilinears
///
///   B_j[i] = ∏_{j' = 0..K_1} eq(z_{j K_1 + j'}, p_{j K_1 + j'}[i])
///
/// as a single K_2-batched MLE over c variables (row-major: each row of K_2 consecutive
/// entries is one i ∈ {0,1}^c).  Returned MLE lives in the extension field.
pub fn build_b_mles<F, EF>(
    batched: &Mle<F, CpuBackend>,
    z: &[EF],
    k1: usize,
    k2: usize,
) -> Mle<EF, CpuBackend>
where
    F: Field,
    EF: ExtensionField<F>,
{
    let k = batched.num_polynomials();
    assert_eq!(k, k1 * k2);
    assert_eq!(z.len(), k);
    let n = batched.num_variables();
    let n_pow = 1usize << n;
    let slice = batched.guts().as_slice();

    // Per-factor (a_k, b_k) so the inner factor evaluates as EF + EF · F (cheap ext-by-base).
    let a: Vec<EF> = z.iter().map(|zk| EF::one() - *zk).collect();
    let b: Vec<EF> = z.iter().map(|zk| *zk + *zk - EF::one()).collect();

    let a_ref = a.as_slice();
    let b_ref = b.as_slice();
    let data: Vec<EF> = (0..n_pow)
        .into_par_iter()
        .flat_map_iter(|i| {
            let row = &slice[i * k..(i + 1) * k];
            (0..k2).map(move |j| {
                let base = j * k1;
                let mut prod = EF::one();
                for jp in 0..k1 {
                    let kk = base + jp;
                    let p = row[kk];
                    let factor = a_ref[kk] + b_ref[kk] * p;
                    prod *= factor;
                }
                prod
            })
        })
        .collect();

    let tensor = Tensor::from(data).reshape([n_pow, k2]);
    Mle::new(tensor)
}

/// Run the two-stage-GKR prover end-to-end on a single batched MLE.
///
/// The split is configurable through `(k1, k2)` so the bench harness can sweep it.
/// Returns the bundled proof; the test harness verifies both stage transcripts and the
/// final-eval consistency.
pub fn simple_two_stage_eq_product_sumcheck<F, EF, Chal>(
    batched: Mle<F, CpuBackend>,
    zeta: Vec<EF>,
    z: Vec<EF>,
    k1: usize,
    k2: usize,
    claim: EF,
    challenger: &mut Chal,
) -> TwoStageEqProductProof<EF>
where
    F: Field + 'static,
    EF: ExtensionField<F> + Send + Sync,
    Chal: FieldChallenger<F>,
{
    let k = batched.num_polynomials();
    assert_eq!(k, k1 * k2);
    assert!(k2.is_power_of_two(), "K_2 must be a power of two for the ζ''' partial-Lagrange");

    // ---- Stage 1: build B_j's and run the eq-prefixed degree-(K_2 + 1) sumcheck.
    let b_mles = build_b_mles::<F, EF>(&batched, &z, k1, k2);
    let stage1_z = vec![EF::one(); k2]; // forces a_j = 0, b_j = 1, factor = B_j[i]
    let stage1_poly = EqProductPoly::<EF, EF>::new(b_mles, zeta.clone(), stage1_z);

    let lambda1: EF = challenger.sample_ext_element();
    let (stage1_proof, mut stage1_evals) = reduce_sumcheck_to_evaluation::<F, EF, _>(
        vec![stage1_poly],
        challenger,
        vec![claim],
        1,
        lambda1,
    );
    let v: Vec<EF> = stage1_evals.pop().expect("stage 1 should return one component-eval vector");
    assert_eq!(v.len(), k2);
    challenger.observe_ext_element_slice(&v);

    // ---- ζ''' challenge → w = partial Lagrange of size K_2.
    let log_k2 = k2.trailing_zeros() as usize;
    let zeta_ppp_vec: Vec<EF> = (0..log_k2).map(|_| challenger.sample_ext_element()).collect();
    let zeta_ppp: Point<EF, CpuBackend> = zeta_ppp_vec.into();
    let w_tensor = partial_lagrange::<EF>(&zeta_ppp);
    let w: Vec<EF> = w_tensor.as_slice().to_vec();
    assert_eq!(w.len(), k2);

    // Stage-2 claim is ∑_j w_j · v_j (the verifier does this in the clear).
    let stage2_claim: EF = w.iter().zip(v.iter()).fold(EF::zero(), |acc, (wj, vj)| acc + *wj * *vj);

    // ---- Stage 2: degree-(K_1 + 1) sumcheck with the K_2-loop done inside the prover's
    // round univariate.
    let stage2_poly =
        EqOuterSumPoly::<F, EF>::new(batched, stage1_proof.point_and_eval.0.to_vec(), z, w, k1, k2);
    let lambda2: EF = challenger.sample_ext_element();
    let (stage2_proof, mut stage2_evals) = reduce_sumcheck_to_evaluation::<F, EF, _>(
        vec![stage2_poly],
        challenger,
        vec![stage2_claim],
        1,
        lambda2,
    );
    let final_evals: Vec<EF> =
        stage2_evals.pop().expect("stage 2 should return one component-eval vector");
    assert_eq!(final_evals.len(), k);
    challenger.observe_ext_element_slice(&final_evals);

    TwoStageEqProductProof { stage1: stage1_proof, v, stage2: stage2_proof, final_evals }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::two_stage_eq_product_verifier::verify_two_stage_eq_product;
    use rand::{distributions::Standard, rngs::StdRng, Rng, SeedableRng};
    use slop_algebra::extension::BinomialExtensionField;
    use slop_baby_bear::{baby_bear_poseidon2::BabyBearDegree4Duplex, BabyBear};
    use slop_challenger::IopCtx;

    type F = BabyBear;
    type EF = BinomialExtensionField<BabyBear, 4>;

    /// End-to-end correctness for a given (K_1, K_2) split with K = K_1 · K_2 = 64.
    ///
    /// Checks:
    /// * (a) stage-1 transcript verifies (degree K_2 + 1),
    /// * (b) stage-2 transcript verifies (degree K_1 + 1),
    /// * (c) each stage-2 component-eval claim equals a host evaluation of p_k at the
    ///   stage-2 sumcheck point η,
    /// * (d) the stage-2 proof's final eval claim equals
    ///   ∑_j w_j · ∏_{j'} eq(z_{jK_1 + j'}, p_{jK_1 + j'}(η))
    ///   recomputed from the host evaluations (which is exactly what the verifier would do).
    fn run_two_stage_eq_product_sumcheck_test(k1: usize, k2: usize, num_variables: u32, seed: u64) {
        let k = k1 * k2;
        let mut rng = StdRng::seed_from_u64(seed);

        // K random base-field MLE columns over c variables.
        let batched = Mle::<F>::rand(&mut rng, k, num_variables);

        // Random ζ ∈ EF^c and z ∈ EF^K.
        let zeta: Vec<EF> =
            (&mut rng).sample_iter::<EF, _>(Standard).take(num_variables as usize).collect();
        let z: Vec<EF> = (&mut rng).sample_iter::<EF, _>(Standard).take(k).collect();

        // True initial claim: ∑_i eq(ζ, i) · ∏_k eq(z_k, p_k[i]).
        let n_pow = 1usize << num_variables;
        let slice = batched.guts().as_slice();
        let eq_full = partial_lagrange::<EF>(&zeta.clone().into());
        let eq_full_slice = eq_full.as_slice();
        let mut claim = EF::zero();
        for i in 0..n_pow {
            let row = &slice[i * k..(i + 1) * k];
            let mut prod = EF::one();
            for j in 0..k {
                let p = row[j];
                let factor = (EF::one() - z[j]) + (z[j] + z[j] - EF::one()) * p;
                prod *= factor;
            }
            claim += eq_full_slice[i] * prod;
        }

        // Prove.
        let mut challenger = BabyBearDegree4Duplex::default_challenger();
        let proof = simple_two_stage_eq_product_sumcheck::<F, EF, _>(
            batched.clone(),
            zeta.clone(),
            z.clone(),
            k1,
            k2,
            claim,
            &mut challenger,
        );

        // Replay the verifier-side transcript via the shared helper, which checks both stage
        // transcripts, the stage-1 → stage-2 claim transition, and the eval-claim consistency.
        let mut verifier = BabyBearDegree4Duplex::default_challenger();
        let zeta_point: Point<EF> = zeta.clone().into();
        let host_evals_at = |eta: &[EF]| batched.eval_at::<EF>(&eta.to_vec().into()).to_vec();
        let (stage1_claim, eta, final_evals) = verify_two_stage_eq_product::<F, EF, _>(
            &proof,
            &zeta_point,
            &z,
            k1,
            k2,
            num_variables as usize,
            &mut verifier,
        )
        .expect("two-stage verification failed");
        assert_eq!(
            stage1_claim, claim,
            "K_1={k1} K_2={k2}: verifier-returned stage1 claim != prover's initial claim",
        );
        let expected_evals = host_evals_at(&eta.into_values());
        assert_eq!(
            final_evals, expected_evals,
            "K_1={k1} K_2={k2}: final evals do not match host evals"
        );
    }

    #[test]
    fn test_two_stage_eq_product_k1_8_k2_8() {
        run_two_stage_eq_product_sumcheck_test(8, 8, 6, 0xc0ffee);
    }

    #[test]
    fn test_two_stage_eq_product_k1_4_k2_16() {
        run_two_stage_eq_product_sumcheck_test(4, 16, 6, 0xc0ffee);
    }

    #[test]
    fn test_two_stage_eq_product_k1_16_k2_4() {
        run_two_stage_eq_product_sumcheck_test(16, 4, 6, 0xc0ffee);
    }

    #[test]
    fn test_two_stage_eq_product_k1_2_k2_32() {
        run_two_stage_eq_product_sumcheck_test(2, 32, 6, 0xc0ffee);
    }

    #[test]
    fn test_two_stage_eq_product_k1_32_k2_2() {
        run_two_stage_eq_product_sumcheck_test(32, 2, 6, 0xc0ffee);
    }
}
