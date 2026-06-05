//! CPU prover for an eq-prefixed product sumcheck — the two-stage-GKR Option 1 shape.
//!
//! Given K base-field MLEs `p_j` over n variables, an extension-field point `ζ ∈ EF^n`, and
//! an extension-field z ∈ EF^K, this module proves the sumcheck
//!
//!   ∑_{x ∈ {0,1}^n} eq(ζ, x) · ∏_{j=1..K} eq(z_j, p_j(x)).
//!
//! Each round's prover message is a degree-(K+1) polynomial that factors as
//!   g_r(t) = eq(ζ_r, t) · h_r(t),
//! where h_r has degree K (the Gruen-style "eq factor pull-out").  We compute h_r at K
//! kernel eval points (t = 0, 2, 3, ..., K), recover h_r(1) from the round claim, apply the
//! cached (K+1)² Lagrange-to-power matrix to get h_r in power form, then multiply by the
//! linear eq factor `(1 - ζ_r) + ζ_r · t` to produce g_r — slop's verifier expects to see
//! the full degree-(K+1) round message.
//!
//! Inner-loop differences from the plain product sumcheck (see `product.rs`):
//! * Each factor is `(1 - z_j) + (2 z_j - 1) · p_j(x, t)` rather than `p_j(x, t)`.  We
//!   precompute `a_j = 1 - z_j` and `b_j = 2 z_j - 1` once.  Per-(x, j) we form
//!   u_j = a_j + b_j · p_j(x, 0)
//!   v_j = b_j · (p_j(x, 1) - p_j(x, 0))
//!   so that factor(t) = u_j + t · v_j and the add-chain trick still walks eval points by
//!   one ext-add each.
//! * The eq prefix E_r(x) = ∏_{i ≤ n-r} eq(ζ_i, x_i) scales the running product per x.
//!   Rather than scaling each of K running products by E_r(x) (which would be K ext × ext
//!   mults per x), we absorb E_r(x) into u_0 and v_0 (2 ext × ext mults per x) so it
//!   propagates through the j = 0 factor and lands in all K running products for free.
//! * Between rounds the eq prefix transitions E_r → E_{r+1} by summing adjacent pairs
//!   (E_{r+1}(y) = E_r(y, 0) + E_r(y, 1)) — no alpha is involved because each Boolean
//!   coordinate's eq factor sums to 1.

use std::{
    any::{Any, TypeId},
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};

use rayon::prelude::*;
use slop_algebra::{
    AbstractExtensionField, AbstractField, ExtensionField, Field, UnivariatePolynomial,
};
use slop_alloc::{CpuBackend, HasBackend};
use slop_multilinear::{partial_lagrange, Mle, Point};
use slop_sumcheck::{
    ComponentPolyEvalBackend, SumCheckPolyFirstRoundBackend, SumcheckPolyBackend, SumcheckPolyBase,
};
use slop_tensor::Tensor;

/// State for an eq-prefixed degree-(K+1) product sumcheck.
///
/// In round 0 the K factors are base-field MLEs (`F` = base, `EF` = ext).  After round 0's
/// fold the K factors become EF too, so the next-round struct is `EqProductPoly<EF, EF>`.
#[derive(Clone, Debug)]
pub struct EqProductPoly<F, EF = F> {
    /// K-batched MLE of the K factors.
    pub mle: Mle<F, CpuBackend>,
    /// Eq prefix tensor `E_r` over the n−r remaining non-eval variables (size 2^(n−r) in
    /// round r).
    pub eq_prefix: Mle<EF, CpuBackend>,
    /// `a[j] = 1 − z_j`.  Precomputed once at construction.
    pub a: Vec<EF>,
    /// `b[j] = 2 z_j − 1`.  Precomputed once at construction.
    pub b: Vec<EF>,
    /// Remaining ζ-coordinates indexed as [ζ_1, …, ζ_remaining]; `last()` is the
    /// ζ-coordinate for the round currently being run (the one we pull out via the Gruen
    /// factor).  Popped each round's fold.
    pub remaining_zetas: Vec<EF>,
}

impl<F, EF> EqProductPoly<F, EF>
where
    F: AbstractField,
    EF: AbstractExtensionField<F> + 'static,
{
    /// Build an [EqProductPoly] from a K-batched base MLE, the ζ point (n elements), and
    /// the z vector (K elements).
    pub fn new(mle: Mle<F, CpuBackend>, zeta: Vec<EF>, z: Vec<EF>) -> Self {
        let k = mle.num_polynomials();
        let n = mle.num_variables() as usize;
        assert_eq!(zeta.len(), n, "zeta must have one ext element per MLE variable");
        assert_eq!(z.len(), k, "z must have one ext element per factor");
        assert!(n >= 1, "need at least one variable");

        let a: Vec<EF> = z.iter().map(|zj| EF::one() - zj.clone()).collect();
        let b: Vec<EF> = z.iter().map(|zj| zj.clone() + zj.clone() - EF::one()).collect();

        // Initial eq prefix E_1 over ζ_1..ζ_{n−1}: a partial Lagrange tensor of size 2^(n−1).
        let zeta_prefix: Point<EF, CpuBackend> = zeta[..n - 1].to_vec().into();
        let eq_prefix_tensor = partial_lagrange(&zeta_prefix);
        let eq_prefix = Mle::new(eq_prefix_tensor);

        Self { mle, eq_prefix, a, b, remaining_zetas: zeta }
    }

    pub fn k(&self) -> usize {
        self.mle.num_polynomials()
    }
}

impl<F, EF> HasBackend for EqProductPoly<F, EF>
where
    F: AbstractField,
    EF: AbstractExtensionField<F>,
{
    type Backend = CpuBackend;
    fn backend(&self) -> &Self::Backend {
        self.mle.backend()
    }
}

impl<F, EF> SumcheckPolyBase for EqProductPoly<F, EF>
where
    F: AbstractField,
    EF: AbstractExtensionField<F>,
{
    fn num_variables(&self) -> u32 {
        self.mle.num_variables()
    }
}

impl<F, EF> ComponentPolyEvalBackend<EqProductPoly<F, EF>, EF> for CpuBackend
where
    F: Field,
    EF: ExtensionField<F>,
{
    fn get_component_poly_evals(poly: &EqProductPoly<F, EF>) -> Vec<EF> {
        // After every variable has been folded the K-batched MLE has a single hypercube
        // point — the K final per-factor evaluation claims sit in the first K entries.
        let k = poly.mle.num_polynomials();
        poly.mle.guts().as_slice()[..k].iter().map(|v| EF::from_base(*v)).collect()
    }
}

// Rounds 2..n — both factor MLE and eq prefix are in EF.
impl<EF> SumcheckPolyBackend<EqProductPoly<EF, EF>, EF> for CpuBackend
where
    EF: Field + 'static,
{
    fn fix_last_variable(poly: EqProductPoly<EF, EF>, alpha: EF) -> EqProductPoly<EF, EF> {
        fix_one_variable(poly, alpha)
    }

    fn sum_as_poly_in_last_variable(
        poly: &EqProductPoly<EF, EF>,
        claim: Option<EF>,
    ) -> UnivariatePolynomial<EF> {
        compute_round_univariate_eq::<EF, EF>(
            &poly.mle,
            &poly.eq_prefix,
            &poly.a,
            &poly.b,
            *poly.remaining_zetas.last().expect("remaining_zetas should not be empty"),
            claim.expect("expected a claim"),
        )
    }
}

// Round 1 (first round): K-batched MLE is base-field, transition to ext-field for round 2+.
impl<F, EF> SumCheckPolyFirstRoundBackend<EqProductPoly<F, EF>, EF> for CpuBackend
where
    F: Field + 'static,
    EF: ExtensionField<F>,
{
    type NextRoundPoly = EqProductPoly<EF, EF>;

    fn fix_t_variables(poly: EqProductPoly<F, EF>, alpha: EF, t: usize) -> EqProductPoly<EF, EF> {
        assert_eq!(t, 1, "EqProductPoly only supports single-variable rounds");
        fix_one_variable(poly, alpha)
    }

    fn sum_as_poly_in_last_t_variables(
        poly: &EqProductPoly<F, EF>,
        claim: Option<EF>,
        t: usize,
    ) -> UnivariatePolynomial<EF> {
        assert_eq!(t, 1, "EqProductPoly only supports single-variable rounds");
        compute_round_univariate_eq::<F, EF>(
            &poly.mle,
            &poly.eq_prefix,
            &poly.a,
            &poly.b,
            *poly.remaining_zetas.last().expect("remaining_zetas should not be empty"),
            claim.expect("expected a claim"),
        )
    }
}

/// Fold the last variable of the K-batched MLE by `alpha` and transition the eq prefix to
/// its next-round form; pops one ζ-coordinate.  Used by both the first-round transition
/// (F → EF) and subsequent same-field rounds.
///
/// The transition is `E_{r+1}(y) = eq(ζ_r, α_r) · (E_r(y, 0) + E_r(y, 1))`.  The
/// pair-sum drops the just-folded variable's eq factor from the prefix; the extra
/// `eq(ζ_r, α_r)` scalar carries the cumulative `C_r = ∏_{r' ≤ r} eq(ζ_{r'}, α_{r'})`
/// that the round-r+1 prover message must include in front of `h_{r+1}(t)`.  Folding the
/// running scalar into the eq prefix means `sum_as_poly` doesn't need to track it
/// separately — the matrix-apply naturally picks it up.
fn fix_one_variable<F, EF>(poly: EqProductPoly<F, EF>, alpha: EF) -> EqProductPoly<EF, EF>
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
    EqProductPoly {
        mle: new_mle,
        eq_prefix: new_eq,
        a: poly.a,
        b: poly.b,
        remaining_zetas: new_zetas,
    }
}

/// Marginalise out the last variable of the eq prefix and scale the result by `scalar`.
/// `scalar` carries the cumulative `eq(ζ_r, α_r)` that needs to land in front of the next
/// round's `h(t)` — folding it in here keeps the prover's per-round message correct without
/// a separate scalar field.
pub(crate) fn sum_pair_eq_prefix_scaled<EF>(
    eq: &Mle<EF, CpuBackend>,
    scalar: EF,
) -> Mle<EF, CpuBackend>
where
    EF: Field,
{
    let size = eq.num_non_zero_entries();
    let slice = eq.guts().as_slice();
    if size <= 1 {
        // After the last fold the prefix has collapsed to a single accumulated scalar;
        // there's nothing more to marginalise out, just rescale.
        let v = slice[0] * scalar;
        let tensor = Tensor::from(vec![v]).reshape([1, 1]);
        return Mle::new(tensor);
    }
    let new_size = size / 2;
    let new_data: Vec<EF> =
        (0..new_size).map(|i| (slice[2 * i] + slice[2 * i + 1]) * scalar).collect();
    let tensor = Tensor::from(new_data).reshape([new_size, 1]);
    Mle::new(tensor)
}

/// Build this round's univariate prover message g_r(t) = eq(ζ_r, t) · h_r(t).
///
/// h_r(t) = ∑_{y ∈ {0,1}^{n−1}} E_r(y) · ∏_{j=1..K} eq(z_j, p_j(y, t))
///        = ∑_y E_r(y) · ∏_j (u_j(y) + t · v_j(y))
/// is computed at K kernel eval points (t = 0, 2, 3, …, K); h_r(1) is recovered from the
/// round claim via (1−ζ_r)·h_r(0) + ζ_r·h_r(1) = claim; the cached F-typed (K+1)²
/// Lagrange matrix turns the K+1 evals into the K+1 power-form coefficients of h_r; and a
/// final linear poly-mul yields g_r (degree K+1, K+2 coefficients).
fn compute_round_univariate_eq<F, EF>(
    mle: &Mle<F, CpuBackend>,
    eq_prefix: &Mle<EF, CpuBackend>,
    a: &[EF],
    b: &[EF],
    zeta_r: EF,
    claim: EF,
) -> UnivariatePolynomial<EF>
where
    F: Field + 'static,
    EF: ExtensionField<F>,
{
    let k = mle.num_polynomials();
    assert_eq!(a.len(), k);
    assert_eq!(b.len(), k);
    let num_vars = mle.num_variables();
    assert!(num_vars > 0, "cannot sum-as-poly a 0-variable MLE");
    let n_half = 1usize << (num_vars - 1);
    assert_eq!(eq_prefix.num_non_zero_entries(), n_half, "eq prefix must have size 2^(n−1)");

    let mle_slice = mle.guts().as_slice();
    let eq_slice = eq_prefix.guts().as_slice();

    // Step 1: kernel evals of h_r at t ∈ {0, 2, 3, …, K}.
    let h_evals: Vec<EF> = (0..n_half)
        .into_par_iter()
        .fold(
            || (vec![EF::zero(); k], vec![EF::zero(); k]),
            |(mut prod, mut acc), x| {
                let lo_base = 2 * x * k;
                let hi_base = lo_base + k;
                let lo_chunk = &mle_slice[lo_base..lo_base + k];
                let hi_chunk = &mle_slice[hi_base..hi_base + k];
                let eq_val = eq_slice[x];

                // j = 0: form (u_0, v_0) and absorb the eq prefix into them so it
                // propagates through all K eval-point running products for free.
                let p_lo = lo_chunk[0];
                let d = hi_chunk[0] - p_lo;
                let u = a[0] + b[0] * p_lo;
                let v = b[0] * d;
                let u_eq = eq_val * u;
                let v_eq = eq_val * v;
                prod[0] = u_eq;
                let mut cur = u_eq + v_eq; // skipped t = 1
                for slot in prod.iter_mut().skip(1) {
                    cur += v_eq;
                    *slot = cur;
                }

                // j = 1..K: multiply each running factor in.
                for j in 1..k {
                    let p_lo_j = lo_chunk[j];
                    let d_j = hi_chunk[j] - p_lo_j;
                    let u_j = a[j] + b[j] * p_lo_j;
                    let v_j = b[j] * d_j;

                    prod[0] *= u_j;
                    let mut cur = u_j + v_j;
                    for slot in prod.iter_mut().skip(1) {
                        cur += v_j;
                        *slot *= cur;
                    }
                }

                for e in 0..k {
                    acc[e] += prod[e];
                }
                (prod, acc)
            },
        )
        .map(|(_, acc)| acc)
        .reduce(
            || vec![EF::zero(); k],
            |mut a, b| {
                for e in 0..k {
                    a[e] += b[e];
                }
                a
            },
        );

    // Step 2: recover h_r(1) from the round claim.
    // claim = g_r(0) + g_r(1) = (1 − ζ_r) h_r(0) + ζ_r h_r(1)
    let one_minus_zeta = EF::one() - zeta_r;
    let h_at_0 = h_evals[0];
    let h_at_1 = (claim - one_minus_zeta * h_at_0) * zeta_r.inverse();

    // Step 3: assemble the K+1 y-values at nodes {0, 1, 2, …, K}.
    let n = k + 1;
    let mut y: Vec<EF> = Vec::with_capacity(n);
    y.push(h_at_0);
    y.push(h_at_1);
    y.extend_from_slice(&h_evals[1..]);

    // Step 4: cached (K+1)² Lagrange-to-power matrix → h_r's power-form coefficients.
    let m = lagrange_matrix::<F>(k);
    let mut h_coefs: Vec<EF> = Vec::with_capacity(n);
    for j in 0..n {
        let row_start = j * n;
        let mut sum = EF::zero();
        for i in 0..n {
            sum += y[i] * m[row_start + i];
        }
        h_coefs.push(sum);
    }

    // Step 5: multiply h_r(t) by eq(ζ_r, t) to get g_r(t).
    //   eq(ζ_r, t) = (1 − ζ_r)(1 − t) + ζ_r · t = (1 − ζ_r) + (2 ζ_r − 1) · t.
    //   So g_r[j] = (1 − ζ_r) · h_r[j] + (2 ζ_r − 1) · h_r[j − 1]   (h_r[−1] = 0).
    let two_zeta_minus_one = zeta_r + zeta_r - EF::one();
    let mut g_coefs: Vec<EF> = vec![EF::zero(); n + 1];
    for j in 0..n {
        g_coefs[j] += one_minus_zeta * h_coefs[j];
        g_coefs[j + 1] += two_zeta_minus_one * h_coefs[j];
    }

    UnivariatePolynomial::new(g_coefs)
}

/// Per-(K, F) cached Lagrange-to-power matrix.  Keyed by `TypeId<F>` so the same global
/// cache works for any field type the prover is instantiated with (base for round 0, the
/// extension for later rounds).
type AnyMatrix = Arc<dyn Any + Send + Sync>;
type LagrangeMatrixCache = Mutex<HashMap<(usize, TypeId), AnyMatrix>>;

pub(crate) fn lagrange_matrix<F: Field + 'static>(k: usize) -> Arc<Vec<F>> {
    static CACHE: OnceLock<LagrangeMatrixCache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    let key = (k, TypeId::of::<F>());
    {
        let guard = cache.lock().unwrap();
        if let Some(v) = guard.get(&key) {
            return v.clone().downcast::<Vec<F>>().expect("matrix cache type mismatch");
        }
    }
    let m: Arc<Vec<F>> = Arc::new(build_lagrange_matrix::<F>(k));
    let any: AnyMatrix = m.clone();
    cache.lock().unwrap().insert(key, any);
    m
}

/// Build the (K+1) × (K+1) Lagrange-to-power matrix for nodes {0, 1, ..., K}.
///
/// `M[j * n + i]` is the coefficient of x^j in the i-th Lagrange basis polynomial
/// L_i(x) = ∏_{q ≠ i} (x - q) / (i - q).  Given evaluations y_i at the K+1 nodes, the
/// power-form coefficients of the interpolating polynomial are
///   coef[j] = ∑_i M[j * n + i] · y[i].
pub(crate) fn build_lagrange_matrix<F: Field>(k: usize) -> Vec<F> {
    let n = k + 1;
    let mut m = vec![F::zero(); n * n];

    // num_coefs / next_coefs scratch reused per i.
    let mut num_coefs: Vec<F> = Vec::with_capacity(n);
    let mut next_coefs: Vec<F> = Vec::with_capacity(n + 1);

    for i in 0..n {
        let xi = F::from_canonical_u32(i as u32);

        // Numerator polynomial ∏_{q ≠ i} (x - q), expanded into power form.
        num_coefs.clear();
        num_coefs.push(F::one());
        for q in 0..n {
            if q == i {
                continue;
            }
            let xq = F::from_canonical_u32(q as u32);
            // new[r+1] += num[r], new[r] -= num[r] * xq
            next_coefs.clear();
            next_coefs.resize(num_coefs.len() + 1, F::zero());
            for (r, &c) in num_coefs.iter().enumerate() {
                next_coefs[r + 1] += c;
                next_coefs[r] -= c * xq;
            }
            std::mem::swap(&mut num_coefs, &mut next_coefs);
        }

        // Denominator = ∏_{q ≠ i} (i - q).  Nonzero because the nodes are distinct.
        let mut denom = F::one();
        for q in 0..n {
            if q == i {
                continue;
            }
            let xq = F::from_canonical_u32(q as u32);
            denom *= xi - xq;
        }
        let denom_inv = denom.inverse();

        for j in 0..n {
            m[j * n + i] = num_coefs[j] * denom_inv;
        }
    }

    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eq_product_verifier::verify_eq_product;
    use rand::{distributions::Standard, rngs::StdRng, Rng, SeedableRng};
    use slop_algebra::extension::BinomialExtensionField;
    use slop_baby_bear::{baby_bear_poseidon2::BabyBearDegree4Duplex, BabyBear};
    use slop_challenger::{CanSample, IopCtx};
    use slop_sumcheck::reduce_sumcheck_to_evaluation;

    type F = BabyBear;
    type EF = BinomialExtensionField<BabyBear, 4>;

    /// Round-trip a full eq-prefixed sumcheck for K=64 factors at n variables.  Uses the
    /// TRUE initial claim — checks (a) the proof transcript-verifies, (b) each component
    /// eval claim equals a host evaluation of p_j at the sumcheck point, and (c) the
    /// proof's final eval claim equals eq(ζ, point) · ∏_j eq(z_j, p_j(point)) computed from
    /// the host evaluations.
    fn run_eq_product_sumcheck_test(k: usize, num_variables: u32, seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);

        // K random base-field MLE columns over n variables.
        let batched = Mle::<F>::rand(&mut rng, k, num_variables);

        // Random ζ ∈ EF^n and z ∈ EF^K.
        let zeta: Vec<EF> =
            (&mut rng).sample_iter::<EF, _>(Standard).take(num_variables as usize).collect();
        let z: Vec<EF> = (&mut rng).sample_iter::<EF, _>(Standard).take(k).collect();

        // True initial claim: ∑_x eq(ζ, x) · ∏_j eq(z_j, p_j(x)).
        let n_pow = 1usize << num_variables;
        let slice = batched.guts().as_slice();
        let eq_full = partial_lagrange::<EF>(&zeta.clone().into());
        let eq_full_slice = eq_full.as_slice();
        let mut claim = EF::zero();
        for i in 0..n_pow {
            let row = &slice[i * k..(i + 1) * k];
            // ∏_j eq(z_j, p_j(x_i)) = ∏_j ((1 − z_j) + (2 z_j − 1) p_j(x_i))
            let mut prod = EF::one();
            for j in 0..k {
                let p = row[j];
                let factor = (EF::one() - z[j]) + (z[j] + z[j] - EF::one()) * p;
                prod *= factor;
            }
            claim += eq_full_slice[i] * prod;
        }

        let poly = EqProductPoly::new(batched.clone(), zeta.clone(), z.clone());

        // Prove via slop's generic sumcheck driver.  One polynomial, so the RLC by
        // `lambda` collapses to identity.
        let mut challenger = BabyBearDegree4Duplex::default_challenger();
        let lambda: EF = challenger.sample();
        let (proof, mut eval_claims_per_poly) = reduce_sumcheck_to_evaluation::<F, EF, _>(
            vec![poly.clone()],
            &mut challenger,
            vec![claim],
            1,
            lambda,
        );

        let component_evals: Vec<EF> = eval_claims_per_poly.pop().unwrap();
        assert_eq!(component_evals.len(), k);

        // (a) Sanity: each component eval claim must match a host evaluation of p_j at the
        // sumcheck point.  In production this match is established via PCS openings.
        let point = proof.point_and_eval.0.clone();
        let host_evals_tensor =
            batched.eval_at::<EF>(&point.iter().copied().collect::<Vec<_>>().into());
        let host_evals: Vec<EF> = host_evals_tensor.to_vec();
        for (j, (claimed, expected)) in component_evals.iter().zip(host_evals.iter()).enumerate() {
            assert_eq!(
                claimed, expected,
                "K={k} j={j}: host MLE eval at sumcheck point != claimed final eval"
            );
        }

        // (b) Transcript + final-eval verification via the shared helper.
        let mut verifier = BabyBearDegree4Duplex::default_challenger();
        let zeta_point: Point<EF> = zeta.clone().into();
        verify_eq_product::<F, EF, _>(
            &proof,
            &zeta_point,
            &z,
            &host_evals,
            k,
            num_variables as usize,
            &mut verifier,
        )
        .expect("eq-product verification failed");
        assert_eq!(proof.univariate_polys.len(), num_variables as usize);
    }

    #[test]
    fn test_eq_product_sumcheck_k64() {
        run_eq_product_sumcheck_test(64, 6, 0xfaceb00c);
    }
}
