//! Prover for the booleanity-batched sumcheck reducing 64 (curr + next)
//! evaluation claims at the two-stage GKR's final point η down to 32
//! curr-only claims at `z_new`, and proving Booleanity of the 32 curr-bit
//! MLEs.  Shared types ([`BooleanityBatched`] / [`BooleanityBatchedProof`] /
//! constants / [`IncBranchingProgram`]) live in `boolean_batched_verifier.rs`.

use rayon::prelude::*;
use slop_algebra::{
    interpolate_univariate_polynomial, ExtensionField, Field, UnivariatePolynomial,
};
use slop_challenger::{FieldChallenger, VariableLengthChallenger};
use slop_multilinear::{Mle, Point};
use slop_sumcheck::PartialSumcheckProof;

use crate::jagged_assist::boolean_batched_verifier::{
    bit_rlc_table, eq_eval_at_int, split_two_stage_finals, BooleanityBatched,
    BooleanityBatchedProof, IncBranchingProgram, LOG_NUM_BITS, NUM_BITS,
};

/// Build the K=64 inc-extension table `inc(z, ·)` as a flat `Vec<EF>` of
/// length `2^c`, with the slice convention matching `partial_lagrange` (bit
/// `b` of the slice index maps to `point[c − 1 − b]`, so `inc_table[k]` =
/// inc-BP eval at `(z, j_pt = Point::from_usize(k, c))`).
fn build_inc_table<F, EF>(z: &Point<EF>, num_real_cols: usize) -> Vec<EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    let c = z.dimension();
    let two_c = 1usize << c;
    let bp = IncBranchingProgram::new(c, num_real_cols);
    (0..two_c)
        .map(|j| {
            let j_pt_base: Point<F> = Point::from_usize(j, c);
            let j_pt_ext: Point<EF> =
                j_pt_base.iter().map(|&b| EF::from_base(b)).collect::<Vec<_>>().into();
            bp.eval(z, &j_pt_ext)
        })
        .collect()
}

impl BooleanityBatched {
    /// Prove the booleanity-batched sumcheck reducing 64 (curr + next) evaluation
    /// claims to 32 curr-only claims at `z_new`.
    ///
    /// - `z`: the point η from the two-stage GKR (`stage2.point_and_eval.0`).
    /// - `p_curr_bits`: the 32 curr-bit MLEs, each of size `2^c`, Boolean-valued
    ///   inside `[0, num_real_pairs)` and zero past.
    /// - `two_stage_finals`: the upstream two-stage GKR proof's `final_evals`
    ///   (length 2·NUM_BITS); split here into `(v_next, v_curr)`.
    /// - `alpha`: per-bit batching scalar for the 3 claims (shift + booleanity +
    ///   curr-eval).
    /// - `rho_bit`: the 5-dim bit-side point. Cross-bit weights are
    ///   `eq(rho_bit, b)` for `b = 0..NUM_BITS`; downstream the verifier reads
    ///   `Σ_b eq(rho_bit, b) · p_b(z_new)` as the single eval claim on the
    ///   `[NUM_BITS, 2^c]` combined-bits MLE at `(z_new, rho_bit)`.
    /// - `challenger`: prover-side host challenger; observed univariate-poly
    ///   coefficients and sampled round challenges modify it in place.
    pub fn prove<F, EF, Chal>(
        &self,
        z: &Point<EF>,
        p_curr_bits: &[Mle<F>],
        two_stage_finals: &[EF],
        alpha: EF,
        rho_bit: &Point<EF>,
        challenger: &mut Chal,
    ) -> BooleanityBatchedProof<EF>
    where
        F: Field,
        EF: ExtensionField<F>,
        Chal: FieldChallenger<F>,
    {
        let Self { num_real_cols, max_prefix_sum } = *self;
        let (v_next, v_curr) = split_two_stage_finals(two_stage_finals);
        assert_eq!(p_curr_bits.len(), NUM_BITS, "expect {NUM_BITS} curr-bit MLEs");
        assert_eq!(rho_bit.dimension(), LOG_NUM_BITS, "rho_bit must be {LOG_NUM_BITS}-dim");

        let c = z.dimension();
        let two_c = 1usize << c;
        for p in p_curr_bits {
            assert_eq!(p.guts().as_slice().len(), two_c, "each curr-bit MLE must have 2^c entries",);
        }

        // λ_b = bit b of max_prefix_sum, promoted to EF for arithmetic.
        let lambda: Vec<EF> = (0..NUM_BITS)
            .map(|b| if (max_prefix_sum >> b) & 1 == 1 { EF::one() } else { EF::zero() })
            .collect();

        // Cross-bit RLC weights `[eq(rho_bit, b)]_{b=0..NUM_BITS}`.
        let eq_rho: Vec<EF> = bit_rlc_table(rho_bit);

        // Initial claim: Σ_b eq(ρ,b) · (v_next_b + α² v_curr_b − λ_b · eq(z, num_real_cols − 1)).
        let eq_at_boundary = eq_eval_at_int::<F, EF>(z, num_real_cols - 1);
        let alpha_sq = alpha * alpha;
        let initial_claim: EF = (0..NUM_BITS)
            .map(|b| eq_rho[b] * (v_next[b] + alpha_sq * v_curr[b] - lambda[b] * eq_at_boundary))
            .sum();

        // Per-round working tables: inc(z, ·), eq(z, ·), and 32 promoted p_b tables.
        let mut inc_t: Vec<EF> = build_inc_table::<F, EF>(z, num_real_cols);
        let mut eq_t: Vec<EF> = Mle::blocking_partial_lagrange(z).guts().as_slice().to_vec();
        let mut p_t: Vec<Vec<EF>> = p_curr_bits
            .iter()
            .map(|p| p.guts().as_slice().iter().map(|&x| EF::from_base(x)).collect())
            .collect();

        let mut univariate_polys: Vec<UnivariatePolynomial<EF>> = Vec::with_capacity(c);
        let mut point: Vec<EF> = Vec::with_capacity(c);
        // Running claim G_{r−1}(rho_{r−1}); seeded with the initial claim so the first
        // round's `G_0(0) + G_0(1)` is what we must verify against.
        let mut running_claim = initial_claim;

        for _round in 0..c {
            let half = inc_t.len() / 2;
            // Compute G(0), G(1), G(−1), G(2).  G(t) = (inc(t) + (α² − α) eq(t)) · q(t)
            //                                          + α · eq(t) · Q(t)
            // where q(t) = Σ_b eq(ρ,b) · p_b(t), Q(t) = Σ_b eq(ρ,b) · p_b²(t).
            let (eval_zero, eval_one, eval_m_one, eval_two) =
                round_evaluations(&inc_t, &eq_t, &p_t, &eq_rho, alpha, half);

            // Sanity: G(0) + G(1) must equal the running claim from the previous round.
            debug_assert_eq!(eval_zero + eval_one, running_claim);

            let uni_poly = interpolate_univariate_polynomial(
                &[EF::zero(), EF::one(), -EF::one(), EF::from_canonical_u8(2)],
                &[eval_zero, eval_one, eval_m_one, eval_two],
            );

            challenger.observe_constant_length_extension_slice(&uni_poly.coefficients);
            univariate_polys.push(uni_poly.clone());

            let rho: EF = challenger.sample_ext_element();
            point.insert(0, rho);
            running_claim = uni_poly.eval_at_point(rho);

            // Fold each table on the last variable.  Top-level Rayon over the 32
            // p_b tables, plus inner-table parallelism via `fold_table_in_place`.
            fold_table_in_place(&mut inc_t, rho, half);
            fold_table_in_place(&mut eq_t, rho, half);
            p_t.par_iter_mut().for_each(|table| {
                fold_table_in_place(table, rho, half);
            });
        }

        let final_evals: Vec<EF> = p_t.iter().map(|p| p[0]).collect();

        BooleanityBatchedProof {
            partial_sumcheck_proof: PartialSumcheckProof {
                univariate_polys,
                claimed_sum: initial_claim,
                point_and_eval: (Point::from(point), running_claim),
            },
            final_evals,
        }
    }
}

/// Compute the round's four evaluations `G(0), G(1), G(−1), G(2)` for the
/// boolean batched polynomial folded at the "last variable" (paired
/// `(lo, hi)` indices).  Parallelised over `rest` via Rayon.
#[inline]
fn round_evaluations<EF: Field>(
    inc_t: &[EF],
    eq_t: &[EF],
    p_t: &[Vec<EF>],
    eq_rho: &[EF],
    alpha: EF,
    half: usize,
) -> (EF, EF, EF, EF) {
    let aa_minus_a = alpha * alpha - alpha;

    (0..half)
        .into_par_iter()
        .map(|rest| {
            let lo = rest * 2;
            let hi = lo + 1;

            let inc_0 = inc_t[lo];
            let inc_1 = inc_t[hi];
            let eq_0 = eq_t[lo];
            let eq_1 = eq_t[hi];
            let inc_m1 = inc_0 + inc_0 - inc_1;
            let inc_2 = inc_1 + inc_1 - inc_0;
            let eq_m1 = eq_0 + eq_0 - eq_1;
            let eq_2 = eq_1 + eq_1 - eq_0;

            let mut sp0 = EF::zero();
            let mut sp1 = EF::zero();
            let mut spm1 = EF::zero();
            let mut sp2 = EF::zero();
            let mut sq0 = EF::zero();
            let mut sq1 = EF::zero();
            let mut sqm1 = EF::zero();
            let mut sq2 = EF::zero();

            for (b, table) in p_t.iter().enumerate() {
                let p0 = table[lo];
                let p1 = table[hi];
                let pm1 = p0 + p0 - p1;
                let p2 = p1 + p1 - p0;
                let bp = eq_rho[b];

                sp0 += bp * p0;
                sp1 += bp * p1;
                spm1 += bp * pm1;
                sp2 += bp * p2;
                sq0 += bp * p0 * p0;
                sq1 += bp * p1 * p1;
                sqm1 += bp * pm1 * pm1;
                sq2 += bp * p2 * p2;
            }

            let g0 = (inc_0 + aa_minus_a * eq_0) * sp0 + alpha * eq_0 * sq0;
            let g1 = (inc_1 + aa_minus_a * eq_1) * sp1 + alpha * eq_1 * sq1;
            let gm1 = (inc_m1 + aa_minus_a * eq_m1) * spm1 + alpha * eq_m1 * sqm1;
            let g2 = (inc_2 + aa_minus_a * eq_2) * sp2 + alpha * eq_2 * sq2;

            (g0, g1, gm1, g2)
        })
        .reduce(
            || (EF::zero(), EF::zero(), EF::zero(), EF::zero()),
            |a, b| (a.0 + b.0, a.1 + b.1, a.2 + b.2, a.3 + b.3),
        )
}

/// Fold the last variable of a single working table by `rho`, replacing
/// `table[rest] = table[2·rest] + rho · (table[2·rest+1] − table[2·rest])`,
/// and shrink the table in-place to length `half`.  Uses Rayon's per-`rest`
/// `par_chunks_mut` to avoid the false aliasing of in-place rewrite.
#[inline]
fn fold_table_in_place<EF: Field>(table: &mut Vec<EF>, rho: EF, half: usize) {
    // Snapshot the pre-fold pairs into the lower half in parallel: rewrite each
    // `table[rest]` from `table[2·rest]` and `table[2·rest + 1]`.  Safe because
    // the read of `table[2·rest+1]` and write of `table[rest]` only collide for
    // `rest = 0`, where the read happens before the write within the closure.
    let folded: Vec<EF> = (0..half)
        .into_par_iter()
        .map(|rest| {
            let lo = rest * 2;
            let hi = lo + 1;
            table[lo] + rho * (table[hi] - table[lo])
        })
        .collect();
    table.truncate(half);
    table.copy_from_slice(&folded);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PREFIX_SUM_BITS;
    use rand::{thread_rng, Rng};
    use slop_algebra::{extension::BinomialExtensionField, AbstractField};
    use slop_baby_bear::{
        baby_bear_poseidon2::{my_bb_16_perm, Perm},
        BabyBear,
    };
    use slop_challenger::DuplexChallenger;
    use slop_multilinear::Mle;

    type F = BabyBear;
    type EF = BinomialExtensionField<F, 4>;
    type Challenger = DuplexChallenger<F, Perm, 16, 8>;

    /// `inc_bp_eval` at integer (i, j) hypercube points equals the boolean
    /// indicator `(j == i + 1) ∧ (j ≤ num_real_cols - 1)`.
    #[test]
    fn inc_bp_matches_indicator_on_hypercube() {
        let num_vars = 4;
        let max_val = 1usize << num_vars;

        for num_real_cols in [1usize, 3, 5, 11, max_val] {
            let bp = IncBranchingProgram::new(num_vars, num_real_cols);
            for i_val in 0..max_val {
                for j_val in 0..max_val {
                    let i_pt: Point<F> = Point::from_usize(i_val, num_vars);
                    let j_pt: Point<F> = Point::from_usize(j_val, num_vars);
                    let actual = bp.eval(&i_pt, &j_pt);
                    let expected = if j_val == i_val + 1 && j_val < num_real_cols {
                        F::one()
                    } else {
                        F::zero()
                    };
                    assert_eq!(
                        actual, expected,
                        "inc_bp({i_val}, {j_val}) with num_real_cols={num_real_cols}: expected {expected:?}, got {actual:?}"
                    );
                }
            }
        }
    }

    /// The BP-derived evaluation agrees with the multilinear extension of
    /// the indicator function at a random extension-field point.
    #[test]
    fn inc_bp_extends_indicator_correctly() {
        let mut rng = thread_rng();
        let num_vars = 5;
        let num_real_cols = 17;
        let max_val = 1usize << num_vars;

        // Build the full 2^(2·num_vars) MLE of the indicator and evaluate it
        // at a random extension point.
        let mut table = vec![F::zero(); max_val * max_val];
        for i_val in 0..max_val {
            for j_val in 0..max_val {
                if j_val == i_val + 1 && j_val < num_real_cols {
                    // Layout matches `Mle::blocking_partial_lagrange([j, i])`:
                    // slice idx k encodes i = k & ((1 << nv) - 1) in lower
                    // num_vars bits, j = (k >> num_vars) in upper num_vars bits.
                    table[j_val * max_val + i_val] = F::one();
                }
            }
        }
        let mle: Mle<F> = Mle::from(table);

        let i_pt: Point<EF> = (0..num_vars).map(|_| rng.gen::<EF>()).collect();
        let j_pt: Point<EF> = (0..num_vars).map(|_| rng.gen::<EF>()).collect();
        // `Mle::blocking_eval_at` reads bits of the slice index against
        // `point[d-1-b]`, so for my `table[j_val * max_val + i_val]` layout
        // (i_val in the lower num_vars bits, j_val in the upper) the combined
        // point must place j first (MSB→LSB) then i.
        let combined: Point<EF> = j_pt.iter().chain(i_pt.iter()).copied().collect();
        let expected = mle.blocking_eval_at::<EF>(&combined).to_vec()[0];

        let bp = IncBranchingProgram::new(num_vars, num_real_cols);
        let actual = bp.eval(&i_pt, &j_pt);

        assert_eq!(actual, expected, "BP eval disagrees with MLE eval");
    }

    /// Build the K=64 bit MLE just like the two-stage GKR uses, then take the
    /// 32 curr-bit rows and the 32 next-bit rows out and feed the booleanity
    /// sumcheck.  Prove → verify round-trip should accept and the verifier's
    /// 32 returned curr-eval claims must equal host-computed `p_b(z_new)`.
    #[test]
    fn boolean_batched_roundtrip() {
        let mut rng = thread_rng();
        let row_counts = [3usize, 7, 0, 11, 4, 0, 9, 2];
        let log_max_row_count = 5;

        // Per existing test, `prefix_sums = scan(0) + last_push` gives
        // num_real_pairs = row_counts.len() prefix-sum pairs (each (col, col+1)).
        let mut prefix_sums: Vec<usize> = row_counts
            .iter()
            .scan(0, |s, r| {
                let v = *s;
                *s += r;
                Some(v)
            })
            .collect();
        prefix_sums.push(*prefix_sums.last().unwrap() + *row_counts.last().unwrap());
        let max_prefix_sum = *prefix_sums.last().unwrap();
        let num_real_cols = prefix_sums.len() - 1;
        let c = (num_real_cols.next_power_of_two().max(2) as u32).trailing_zeros() as usize;
        let _ = log_max_row_count;

        // Build the 32 curr-bit MLEs.  `p_b[col]` = bit b of prefix_sums[col]
        // for `col < num_real_cols`, zero past.  Each MLE has 2^c entries.
        let two_c = 1usize << c;
        let curr_bits: Vec<Mle<F>> = (0..NUM_BITS)
            .map(|b| {
                let table: Vec<F> = (0..two_c)
                    .map(|col| {
                        if col < num_real_cols && ((prefix_sums[col] >> b) & 1) == 1 {
                            F::one()
                        } else {
                            F::zero()
                        }
                    })
                    .collect();
                Mle::from(table)
            })
            .collect();

        // Pick a random η (the two-stage's stage-2 point).
        let z_eta: Point<EF> = (0..c).map(|_| rng.gen::<EF>()).collect();

        // Compute the 32 next-bit and curr-bit evaluations at η directly
        // (these would normally come from the two-stage GKR's final_evals).
        let v_curr: Vec<EF> =
            curr_bits.iter().map(|p| p.blocking_eval_at::<EF>(&z_eta).to_vec()[0]).collect();
        let v_next: Vec<EF> = (0..NUM_BITS)
            .map(|b| {
                let table: Vec<F> = (0..two_c)
                    .map(|col| {
                        if col < num_real_cols && ((prefix_sums[col + 1] >> b) & 1) == 1 {
                            F::one()
                        } else {
                            F::zero()
                        }
                    })
                    .collect();
                Mle::from(table).blocking_eval_at::<EF>(&z_eta).to_vec()[0]
            })
            .collect();

        // Sample α and ρ_bit (5-dim) from a shared FS state for prover and verifier.
        let default_perm = my_bb_16_perm();
        let mut prover_ch = Challenger::new(default_perm.clone());
        let mut verifier_ch = Challenger::new(default_perm);

        let alpha: EF = prover_ch.sample_ext_element();
        let rho_bit_vec: Vec<EF> =
            (0..LOG_NUM_BITS).map(|_| prover_ch.sample_ext_element()).collect();
        let rho_bit: Point<EF> = rho_bit_vec.into();
        let _: EF = verifier_ch.sample_ext_element();
        for _ in 0..LOG_NUM_BITS {
            let _: EF = verifier_ch.sample_ext_element();
        }

        // Interleave (v_next, v_curr) back into the two-stage `final_evals` layout
        // expected by `BooleanityBatched::prove/verify`.
        let mut two_stage_finals = vec![EF::zero(); 2 * NUM_BITS];
        for b in 0..NUM_BITS {
            two_stage_finals[2 * (PREFIX_SUM_BITS - 1 - b)] = v_next[b];
            two_stage_finals[2 * (PREFIX_SUM_BITS - 1 - b) + 1] = v_curr[b];
        }

        let cfg = BooleanityBatched::new(num_real_cols, max_prefix_sum);
        let proof = cfg.prove::<F, EF, Challenger>(
            &z_eta,
            &curr_bits,
            &two_stage_finals,
            alpha,
            &rho_bit,
            &mut prover_ch,
        );

        let (combined_point, p_claim) = cfg
            .verify::<F, EF, Challenger>(
                &proof,
                &z_eta,
                &two_stage_finals,
                alpha,
                &rho_bit,
                &mut verifier_ch,
            )
            .expect("verifier must accept honest proof");

        // The verifier's returned single P claim must equal the actual eval
        // of the combined [NUM_BITS, 2^c] bits MLE at (z_new, ρ_bit).
        assert_eq!(combined_point.dimension(), c + LOG_NUM_BITS);
        let z_new: Point<EF> = combined_point.iter().take(c).copied().collect::<Vec<_>>().into();
        let expected_p_claim: EF = (0..NUM_BITS)
            .map(|b| {
                let actual_pb = curr_bits[b].blocking_eval_at::<EF>(&z_new).to_vec()[0];
                bit_rlc_table(&rho_bit)[b] * actual_pb
            })
            .sum();
        assert_eq!(p_claim, expected_p_claim, "combined P claim mismatch");
    }
}
