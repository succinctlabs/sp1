//! "2-to-1" reductions for multilinear PCS.
//!
//! Given a multilinear `h` in `n` variables and two evaluation claims
//! `(z, A)` and `(z', B)` with `A = h(z)`, `B = h(z')`, reduce them to
//! a single claim `(z'', C)` with `C = h(z'')`.  The resulting claim can
//! then be discharged by a single BaseFold call.
//!
//! Two options are implemented:
//!
//! - **Option 1 (univariate-on-the-line):** prover sends the degree-`n`
//!   univariate `F(T) = h(z + T (z' − z))`, verifier samples a scalar `λ'`
//!   and the new claim is `(z + λ'(z' − z), F(λ'))`.  Wire: `n + 1` EF
//!   values.  One round.
//!
//! - **Option 2 (batched sumcheck with Gruen + 1-accumulator-per-track):**
//!   verifier runs an `n`-round sumcheck reducing
//!   `A = Σⱼ eq(z, j) h(j)` and `B = Σⱼ eq(z', j) h(j)` simultaneously, with
//!   the verifier tracking the two sub-claims separately.  Wire: `2n` EF
//!   values (two `G(0)` accumulators per round).  Both round univariates
//!   factor as `eq(z_round, t) · H(t)` with `H` linear, so a single
//!   evaluation `G(0)` plus the previous-round sub-claim determines the
//!   full degree-2 `G`.
//!
//! Both options are pure-multilinear primitives — no PCS, no field-
//! specific assumptions beyond a `FieldChallenger`.

#![allow(dead_code)] // public API used downstream once wired into the jagged prover

use serde::{Deserialize, Serialize};
use slop_algebra::{
    interpolate_univariate_polynomial, ExtensionField, Field, UnivariatePolynomial,
};
use slop_challenger::FieldChallenger;
use std::fmt;

use crate::{Mle, Point};

/// Failures detected by the verifier.
#[derive(Debug, Clone)]
pub enum TwoToOneError {
    Option1ClaimAtZero,
    Option1ClaimAtOne,
    Option2InconsistentFinalEval,
    Option2DimensionMismatch,
}

impl fmt::Display for TwoToOneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Option1ClaimAtZero => write!(f, "option 1: F(0) != claim_z"),
            Self::Option1ClaimAtOne => write!(f, "option 1: F(1) != claim_z'"),
            Self::Option2InconsistentFinalEval => {
                write!(f, "option 2: the two tracks disagree on h(ρ)")
            }
            Self::Option2DimensionMismatch => write!(f, "option 2: z / z' dimension mismatch"),
        }
    }
}

impl std::error::Error for TwoToOneError {}

// =========================================================================
// Option 1: univariate-on-the-line.
// =========================================================================

/// Proof for the Option-1 reduction.  Carries the coefficients of `F(T)`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Option1Proof<EF> {
    pub f: UnivariatePolynomial<EF>,
}

/// Prove the 2-to-1 reduction via Option 1.
///
/// Returns the proof, the new claim point `z''`, and the new claim
/// `h(z'') = F(λ')`.
pub fn prove_two_to_one_option1<F, EF, Chal>(
    h: &Mle<EF>,
    z: &Point<EF>,
    z_prime: &Point<EF>,
    challenger: &mut Chal,
) -> (Option1Proof<EF>, Point<EF>, EF)
where
    F: Field,
    EF: ExtensionField<F> + 'static,
    Chal: FieldChallenger<F>,
{
    let n = z.dimension();
    assert_eq!(z_prime.dimension(), n);
    assert_eq!(h.num_variables() as usize, n);
    assert_eq!(h.num_polynomials(), 1);

    // F has degree n, so n + 1 distinct interpolation nodes determine it.
    let ts: Vec<EF> = (0..=n).map(|k| EF::from_canonical_usize(k)).collect();
    let evals: Vec<EF> = ts
        .iter()
        .map(|&t| {
            let pt: Point<EF> =
                (0..n).map(|i| *z[i] + t * (*z_prime[i] - *z[i])).collect::<Vec<_>>().into();
            h.eval_at(&pt).to_vec()[0]
        })
        .collect();

    let f = interpolate_univariate_polynomial(&ts, &evals);

    // Observe F's coefficients in the same order as the verifier.
    for &c in &f.coefficients {
        challenger.observe_ext_element(c);
    }
    let lambda_prime: EF = challenger.sample_ext_element();

    let z_pp: Point<EF> =
        (0..n).map(|i| *z[i] + lambda_prime * (*z_prime[i] - *z[i])).collect::<Vec<_>>().into();
    let claim_z_pp = f.eval_at_point(lambda_prime);

    (Option1Proof { f }, z_pp, claim_z_pp)
}

/// Verify the Option-1 reduction.
///
/// Checks that `F(0) == claim_z` and `F(1) == claim_z'`, then samples
/// `λ'`, returns the new claim point and value.
pub fn verify_two_to_one_option1<F, EF, Chal>(
    proof: &Option1Proof<EF>,
    z: &Point<EF>,
    z_prime: &Point<EF>,
    claim_z: EF,
    claim_z_prime: EF,
    challenger: &mut Chal,
) -> Result<(Point<EF>, EF), TwoToOneError>
where
    F: Field,
    EF: ExtensionField<F>,
    Chal: FieldChallenger<F>,
{
    let n = z.dimension();
    assert_eq!(z_prime.dimension(), n);

    // Observe in the same order as the prover.
    for &c in &proof.f.coefficients {
        challenger.observe_ext_element(c);
    }
    let lambda_prime: EF = challenger.sample_ext_element();

    let f_zero = proof.f.eval_at_point(EF::zero());
    if f_zero != claim_z {
        return Err(TwoToOneError::Option1ClaimAtZero);
    }
    let f_one = proof.f.eval_at_point(EF::one());
    if f_one != claim_z_prime {
        return Err(TwoToOneError::Option1ClaimAtOne);
    }

    let z_pp: Point<EF> =
        (0..n).map(|i| *z[i] + lambda_prime * (*z_prime[i] - *z[i])).collect::<Vec<_>>().into();
    let claim_z_pp = proof.f.eval_at_point(lambda_prime);
    Ok((z_pp, claim_z_pp))
}

// =========================================================================
// Option 2: batched sumcheck with Gruen + 1-accumulator-per-track.
// =========================================================================

/// One round's wire message for Option 2.
///
/// Per round, the prover sends only `G_T1(0)` and `G_T2(0)` — the two
/// sub-claims' evaluations at `t = 0`.  Each `G(t)` factors as
/// `eq(z_round, t) · H(t)` with `H` linear, so one evaluation plus the
/// previous-round sub-claim determines the full round univariate.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Option2RoundMessage<EF> {
    pub g_t1_zero: EF,
    pub g_t2_zero: EF,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Option2Proof<EF> {
    pub rounds: Vec<Option2RoundMessage<EF>>,
}

/// Prove the 2-to-1 reduction via Option 2 (batched sumcheck).
///
/// Returns the proof, the sumcheck point `ρ` (in original-variable order),
/// and the new claim `h(ρ)`.
pub fn prove_two_to_one_option2<F, EF, Chal>(
    h: &Mle<EF>,
    z: &Point<EF>,
    z_prime: &Point<EF>,
    claim_z: EF,
    claim_z_prime: EF,
    challenger: &mut Chal,
) -> (Option2Proof<EF>, Point<EF>, EF)
where
    F: Field,
    EF: ExtensionField<F> + 'static,
    Chal: FieldChallenger<F>,
{
    let n = z.dimension();
    assert_eq!(z_prime.dimension(), n);
    assert_eq!(h.num_variables() as usize, n);
    assert_eq!(h.num_polynomials(), 1);

    // Initial state.  h_current is folded each round; the eq tables hold
    // `partial_lagrange(z[0..n-r-1])` and the analogous z' table — i.e. the
    // eq factors for variables that haven't been processed yet (excluding
    // the current round's Gruen variable, which is z[n-r-1] for round r).
    let mut h_current: Vec<EF> = h.guts().as_slice().to_vec();
    let z_slice: Vec<EF> = z.iter().copied().take(n.saturating_sub(1)).collect();
    let zp_slice: Vec<EF> = z_prime.iter().copied().take(n.saturating_sub(1)).collect();
    let mut eq_z: Vec<EF> = partial_lagrange_eq_table::<EF>(&z_slice);
    let mut eq_zp: Vec<EF> = partial_lagrange_eq_table::<EF>(&zp_slice);

    let mut a_k: EF = claim_z;
    let mut b_k: EF = claim_z_prime;
    let mut rhos: Vec<EF> = Vec::with_capacity(n);
    let mut rounds: Vec<Option2RoundMessage<EF>> = Vec::with_capacity(n);

    // Slop convention: variable `n-1` is the LSB of the MLE index, so
    // "fix last variable" folds consecutive even/odd pairs and the eq table
    // for the remaining variables (z[0..k]) has the LAST variable of that
    // prefix at the LSB of its own index — i.e. dropping it is again an
    // even/odd sum-fold.
    for r in 0..n {
        let half = 1usize << (n - r - 1);
        // The Gruen factor for this round: eq(z[n-r-1], t).
        let z_round = *z[n - r - 1];
        let zp_round = *z_prime[n - r - 1];

        // Inner sum at t = 0 (before the Gruen factor): sum over j of
        // eq_table_remaining[j] * h_current[2j] (the even-index entries hold
        // h with current last variable = 0).
        let mut inner_z = EF::zero();
        let mut inner_zp = EF::zero();
        for j in 0..half {
            let h_low = h_current[2 * j];
            inner_z += eq_z[j] * h_low;
            inner_zp += eq_zp[j] * h_low;
        }

        let g_t1_zero = (EF::one() - z_round) * inner_z;
        let g_t2_zero = (EF::one() - zp_round) * inner_zp;

        challenger.observe_ext_element(g_t1_zero);
        challenger.observe_ext_element(g_t2_zero);
        let rho: EF = challenger.sample_ext_element();
        rhos.push(rho);
        rounds.push(Option2RoundMessage { g_t1_zero, g_t2_zero });

        a_k = g_round_at_rho(g_t1_zero, a_k, z_round, rho);
        b_k = g_round_at_rho(g_t2_zero, b_k, zp_round, rho);

        // Fold h by `rho` on consecutive even/odd pairs.
        let mut h_new = Vec::with_capacity(half);
        for j in 0..half {
            let lo = h_current[2 * j];
            let hi = h_current[2 * j + 1];
            h_new.push(lo + rho * (hi - lo));
        }
        h_current = h_new;

        // Shrink the eq tables by sum-folding consecutive even/odd pairs
        // (drops the LAST variable of z[0..n-r-1] from the table — that's
        // z[n-r-2], the next round's Gruen), then multiply by this round's
        // eq factor so the table carries the cumulative scalar
        // `C_r = Π_{i<r} eq(z[n-1-i], ρ_i)`.  This makes
        // `Σ_j eq_z[j] * h_current[2j]` equal to `C_{r+1} * H_T1_raw(0)`
        // directly, so the prover's `g_t1_zero` is `G_T1_actual(0)` and the
        // verifier's identity `A_k = G(0) + G(1)` holds.
        let eq_z_factor = (EF::one() - z_round) * (EF::one() - rho) + z_round * rho;
        let eq_zp_factor = (EF::one() - zp_round) * (EF::one() - rho) + zp_round * rho;
        if half > 1 {
            let next = half / 2;
            let mut eq_z_new = Vec::with_capacity(next);
            let mut eq_zp_new = Vec::with_capacity(next);
            for j in 0..next {
                eq_z_new.push(eq_z_factor * (eq_z[2 * j] + eq_z[2 * j + 1]));
                eq_zp_new.push(eq_zp_factor * (eq_zp[2 * j] + eq_zp[2 * j + 1]));
            }
            eq_z = eq_z_new;
            eq_zp = eq_zp_new;
        } else {
            eq_z.clear();
            eq_zp.clear();
        }
    }

    debug_assert_eq!(h_current.len(), 1);
    let h_rho = h_current[0];

    // a_k now equals eq(z, rho) * h(rho); the final h(rho) we send is
    // simply h_current[0] from the folded MLE.  The verifier will check
    // a_k == eq(z, rho) * h(rho) and b_k == eq(z', rho) * h(rho).

    // Build the sumcheck point in original-variable order: rhos[r] fixed
    // variable n-1-r, so original-order[k] = rhos[n-1-k].
    let point_orig: Point<EF> = (0..n).map(|k| rhos[n - 1 - k]).collect::<Vec<_>>().into();

    (Option2Proof { rounds }, point_orig, h_rho)
}

/// Verify the Option-2 reduction.
///
/// Returns the sumcheck point `ρ` and the final claim `h(ρ)` (recovered
/// from either of the two tracks, after a consistency check).
pub fn verify_two_to_one_option2<F, EF, Chal>(
    proof: &Option2Proof<EF>,
    z: &Point<EF>,
    z_prime: &Point<EF>,
    claim_z: EF,
    claim_z_prime: EF,
    final_h_rho: EF,
    challenger: &mut Chal,
) -> Result<(Point<EF>, EF), TwoToOneError>
where
    F: Field,
    EF: ExtensionField<F>,
    Chal: FieldChallenger<F>,
{
    let n = z.dimension();
    if z_prime.dimension() != n || proof.rounds.len() != n {
        return Err(TwoToOneError::Option2DimensionMismatch);
    }

    let mut a_k = claim_z;
    let mut b_k = claim_z_prime;
    let mut rhos: Vec<EF> = Vec::with_capacity(n);
    for (r, msg) in proof.rounds.iter().enumerate() {
        challenger.observe_ext_element(msg.g_t1_zero);
        challenger.observe_ext_element(msg.g_t2_zero);
        let rho: EF = challenger.sample_ext_element();
        rhos.push(rho);

        let z_round = *z[n - r - 1];
        let zp_round = *z_prime[n - r - 1];

        a_k = g_round_at_rho(msg.g_t1_zero, a_k, z_round, rho);
        b_k = g_round_at_rho(msg.g_t2_zero, b_k, zp_round, rho);
    }

    // After all rounds, a_k = eq(z, rho) * h(rho) and b_k = eq(z', rho) * h(rho).
    // The prover has sent h(rho) directly.  Check both tracks agree.
    let point_orig: Point<EF> = (0..n).map(|k| rhos[n - 1 - k]).collect::<Vec<_>>().into();

    let eq_z_rho = full_eq_eval(z, &point_orig);
    let eq_zp_rho = full_eq_eval(z_prime, &point_orig);

    if a_k != eq_z_rho * final_h_rho {
        return Err(TwoToOneError::Option2InconsistentFinalEval);
    }
    if b_k != eq_zp_rho * final_h_rho {
        return Err(TwoToOneError::Option2InconsistentFinalEval);
    }

    Ok((point_orig, final_h_rho))
}

// =========================================================================
// Internal helpers.
// =========================================================================

/// Build `partial_lagrange(point)` as a plain `Vec<EF>` of length `1 << point.len()`.
fn partial_lagrange_eq_table<EF: Field>(point: &[EF]) -> Vec<EF> {
    let n = point.len();
    if n == 0 {
        return vec![EF::one()];
    }
    let mut out = vec![EF::one(); 1usize << n];
    for (k, &z_k) in point.iter().enumerate() {
        let stride = 1usize << (n - 1 - k);
        let block = stride * 2;
        for base in (0..(1usize << n)).step_by(block) {
            for j in 0..stride {
                let v = out[base + j];
                out[base + j] = v * (EF::one() - z_k);
                out[base + j + stride] = v * z_k;
            }
        }
    }
    out
}

/// Dot product of two equal-length slices.
fn dot_product<EF: Field>(a: &[EF], b: &[EF]) -> EF {
    let mut acc = EF::zero();
    for (x, y) in a.iter().zip(b.iter()) {
        acc += *x * *y;
    }
    acc
}

/// Given `G(0)` and `A_k = G(0) + G(1)`, reconstruct `G(ρ)` using the
/// Gruen factorization `G(t) = eq(z_round, t) · H(t)` with `H` linear.
///
/// Derivation: H(0) = G(0)/(1 − z_round), H(1) = G(1)/z_round, then
/// H(ρ) = (1 − ρ) H(0) + ρ H(1), and G(ρ) = eq(z_round, ρ) · H(ρ).
/// If z_round = 0 then G(1) = 0 so H is determined by H(0) = G(0);
/// likewise if z_round = 1 then G(0) = 0 and H(1) = G(1).
fn g_round_at_rho<EF: Field>(g_zero: EF, a_k: EF, z_round: EF, rho: EF) -> EF {
    let g_one = a_k - g_zero;
    let one_minus_z = EF::one() - z_round;
    // H_round is linear: H(0) and H(1) recovered from G's structure.
    let h_zero = if one_minus_z.is_zero() {
        // z_round == 1: G(t) = t · H(t), so G(0) = 0 and H(0) is free —
        // determined by linearity through (1, H(1)).  Pick H(0) so that
        // H(0) + (H(1)-H(0))·ρ matches; equivalently extrapolate from H(1).
        // In this branch H(0) doesn't matter for round soundness in EF,
        // but we set it to G(1) - G(1) = 0 to avoid panics.
        EF::zero()
    } else {
        g_zero * one_minus_z.inverse()
    };
    let h_one = if z_round.is_zero() { EF::zero() } else { g_one * z_round.inverse() };
    let h_rho = h_zero + rho * (h_one - h_zero);
    let eq_round_rho = one_minus_z + (z_round + z_round - EF::one()) * rho;
    // eq(z_round, rho) = (1 − z_round)(1 − ρ) + z_round · ρ
    //                  = (1 − z_round) + (2 z_round − 1) · ρ
    eq_round_rho * h_rho
}

/// `eq(p, q) = Π_k eq(p[k], q[k])` for two n-variate points.
fn full_eq_eval<EF: Field>(p: &Point<EF>, q: &Point<EF>) -> EF {
    assert_eq!(p.dimension(), q.dimension());
    let mut acc = EF::one();
    for k in 0..p.dimension() {
        let pk = *p[k];
        let qk = *q[k];
        acc *= (EF::one() - pk) * (EF::one() - qk) + pk * qk;
    }
    acc
}

// =========================================================================
// Tests.
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};
    use slop_algebra::{extension::BinomialExtensionField, AbstractField};
    use slop_baby_bear::{baby_bear_poseidon2::BabyBearDegree4Duplex, BabyBear};
    use slop_challenger::IopCtx;
    use slop_tensor::Tensor;

    type F = BabyBear;
    type EF = BinomialExtensionField<F, 4>;
    type Chal = <BabyBearDegree4Duplex as IopCtx>::Challenger;

    fn fresh_challenger() -> Chal {
        BabyBearDegree4Duplex::default_challenger()
    }

    fn random_setup(n: usize, seed: u64) -> (Mle<EF>, Point<EF>, Point<EF>, EF, EF) {
        use rand::Rng;
        let mut rng = StdRng::seed_from_u64(seed);
        let h_data: Vec<EF> = (0..(1usize << n)).map(|_| rng.gen()).collect();
        let mut tensor = Tensor::from(h_data);
        tensor.reshape_in_place([1usize << n, 1usize]);
        let h = Mle::new(tensor);
        let z: Point<EF> = (0..n).map(|_| rng.gen()).collect::<Vec<_>>().into();
        let zp: Point<EF> = (0..n).map(|_| rng.gen()).collect::<Vec<_>>().into();
        let claim_z = h.eval_at(&z).to_vec()[0];
        let claim_zp = h.eval_at(&zp).to_vec()[0];
        (h, z, zp, claim_z, claim_zp)
    }

    fn check_option_returns_consistent_claim(h: &Mle<EF>, z_pp: &Point<EF>, prover_claim: EF) {
        let direct = h.eval_at(z_pp).to_vec()[0];
        assert_eq!(direct, prover_claim);
    }

    #[test]
    fn option1_roundtrip() {
        for &n in &[1usize, 4, 8] {
            let (h, z, zp, az, azp) = random_setup(n, 0xC0DE);
            let mut p_chal = fresh_challenger();
            let mut v_chal = fresh_challenger();

            let (proof, z_pp_p, claim_p) =
                prove_two_to_one_option1::<F, EF, _>(&h, &z, &zp, &mut p_chal);
            let (z_pp_v, claim_v) =
                verify_two_to_one_option1::<F, EF, _>(&proof, &z, &zp, az, azp, &mut v_chal)
                    .unwrap();

            assert_eq!(
                z_pp_p.iter().copied().collect::<Vec<_>>(),
                z_pp_v.iter().copied().collect::<Vec<_>>()
            );
            assert_eq!(claim_p, claim_v);
            check_option_returns_consistent_claim(&h, &z_pp_p, claim_p);
        }
    }

    #[test]
    fn option1_rejects_corrupt_proof() {
        let (h, z, zp, az, azp) = random_setup(6, 0xBAD);
        let mut p_chal = fresh_challenger();
        let (mut proof, _z_pp, _claim) =
            prove_two_to_one_option1::<F, EF, _>(&h, &z, &zp, &mut p_chal);

        // Bump the constant term — F(0) no longer matches `az`.
        proof.f.coefficients[0] += EF::one();
        let mut v_chal = fresh_challenger();
        let res = verify_two_to_one_option1::<F, EF, _>(&proof, &z, &zp, az, azp, &mut v_chal);
        assert!(matches!(res, Err(TwoToOneError::Option1ClaimAtZero)));
    }

    #[test]
    fn option2_roundtrip() {
        for &n in &[1usize, 4, 8] {
            let (h, z, zp, az, azp) = random_setup(n, 0xC0DE);
            let mut p_chal = fresh_challenger();
            let mut v_chal = fresh_challenger();

            let (proof, z_pp_p, claim_p) =
                prove_two_to_one_option2::<F, EF, _>(&h, &z, &zp, az, azp, &mut p_chal);
            let (z_pp_v, claim_v) = verify_two_to_one_option2::<F, EF, _>(
                &proof,
                &z,
                &zp,
                az,
                azp,
                claim_p,
                &mut v_chal,
            )
            .unwrap();

            assert_eq!(
                z_pp_p.iter().copied().collect::<Vec<_>>(),
                z_pp_v.iter().copied().collect::<Vec<_>>()
            );
            assert_eq!(claim_p, claim_v);
            check_option_returns_consistent_claim(&h, &z_pp_p, claim_p);
        }
    }

    #[test]
    fn option2_rejects_corrupt_proof() {
        let (h, z, zp, az, azp) = random_setup(6, 0xBAD2);
        let mut p_chal = fresh_challenger();
        let (mut proof, _z_pp, claim) =
            prove_two_to_one_option2::<F, EF, _>(&h, &z, &zp, az, azp, &mut p_chal);

        // Corrupt round 0's first accumulator.
        proof.rounds[0].g_t1_zero += EF::one();
        let mut v_chal = fresh_challenger();
        let res =
            verify_two_to_one_option2::<F, EF, _>(&proof, &z, &zp, az, azp, claim, &mut v_chal);
        assert!(matches!(res, Err(TwoToOneError::Option2InconsistentFinalEval)));
    }

    #[test]
    fn both_options_agree_on_h_at_new_point() {
        // Sanity: both reductions should produce a valid h(z'') claim that
        // matches direct evaluation.  The z'' points differ between options
        // (because the protocols sample independently), but each option's
        // returned (z'', claim) pair must satisfy claim == h(z'').
        let n = 8;
        let (h, z, zp, az, azp) = random_setup(n, 0xC0DE);

        let mut chal1 = fresh_challenger();
        let (_p1, z_pp_1, c_1) = prove_two_to_one_option1::<F, EF, _>(&h, &z, &zp, &mut chal1);
        check_option_returns_consistent_claim(&h, &z_pp_1, c_1);

        let mut chal2 = fresh_challenger();
        let (_p2, z_pp_2, c_2) =
            prove_two_to_one_option2::<F, EF, _>(&h, &z, &zp, az, azp, &mut chal2);
        check_option_returns_consistent_claim(&h, &z_pp_2, c_2);
    }
}
