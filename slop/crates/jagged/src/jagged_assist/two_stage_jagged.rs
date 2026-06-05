//! Two-stage GKR replacement for the jagged-eval verifier's per-column
//! `full_lagrange_eval` loop.
//!
//! The verifier's reconciliation step computes
//!
//!   Σ_{col < num_real_pairs} z_col_eq[col] · L(merged_prefix_sum[col], ζ_sumcheck)
//!
//! where `merged_prefix_sum[col]` is the bit-interleaving of
//! `prefix_sums[col]` and `prefix_sums[col+1]`, and `ζ_sumcheck` is the random
//! point returned by the inner (assist + α · geq) sumcheck. That sum can be
//! re-cast as the two-stage-GKR shape from [`crate::two_stage_eq_product`]:
//!
//!   Σ_i eq(ζ_outer, i) · ∏_k eq(z_k, p_k[i])
//!
//! with the identifications
//!
//! * `i ↔ col` (over the column hypercube of dimension `c = z_col.dim()`);
//! * `ζ_outer ↔ z_col`;
//! * `z_k ↔ ζ_sumcheck[k]` for the K_actual = 2(log_m+1) "real" bit positions,
//!   zero-padded out to K = 64;
//! * `p_k[i] ↔ k-th bit of merged_prefix_sum[i]`, with all-zero rows for the
//!   padded K range and all-zero columns for `i ≥ num_real_pairs`.
//!
//! **Padding handling.** Zero-padding both `p_k` and `z_k` for `k ≥ K_actual`
//! is "invisible" — each factor `eq(0, 0) = 1` collapses to the identity, so
//! the inner product is unchanged. Zero-padding the column hypercube for
//! `col ≥ num_real_pairs` is *not* invisible: the merged_prefix_sum for those
//! cols is `0`, so the inner product evaluates to a closed-form constant
//! `L_zero(ζ_sumcheck) = ∏_{k < K_actual} (1 − ζ_sumcheck[k])` (the bits beyond
//! `K_actual` are padding zeros, so their `eq(0, 0) = 1` factor drops). The
//! prover claims the **full** hypercube sum; the verifier recovers the
//! per-real-col sum as
//!
//!   real_sum = full_hypercube_sum − L_zero(ζ_sumcheck) · (1 − sum_z_first_n),
//!
//! where `sum_z_first_n` is the existing helper from `geq.rs`.

use rayon::prelude::*;
use slop_algebra::{ExtensionField, Field};
use slop_alloc::CpuBackend;
use slop_challenger::FieldChallenger;
use slop_multilinear::{Mle, Point};
use slop_tensor::Tensor;

use crate::two_stage_eq_product_prover::simple_two_stage_eq_product_sumcheck;
use crate::two_stage_eq_product_verifier::TwoStageEqProductProof;

/// K = K_1 · K_2 for the two-stage GKR — the bit-width of the merged prefix
/// sum (= 2 × 32 = 64). Real prefix sums are always < 2^32 in practice; the
/// upper bits are zero-padded.
pub const K: usize = 64;
/// Per-prefix-sum bit width (= K / 2). All real prefix sums must fit in
/// `PREFIX_SUM_BITS` bits.
pub const PREFIX_SUM_BITS: usize = K / 2;

/// `(K_1, K_2)` split for the two-stage GKR. (8, 8) is the bench-favored
/// balanced split. The choice is opaque to the protocol — both sides must
/// agree on the same split.
pub const K1: usize = 8;
pub const K2: usize = 8;

/// Closed-form evaluation `L(0, ζ_sumcheck_padded) = ∏_k eq(0, ζ_padded[k])`.
///
/// Since padded bits `[K_actual..K)` contribute `eq(0, 0) = 1`, this reduces
/// to `∏_{k < K_actual} (1 − ζ_sumcheck[k])` — i.e. the verifier evaluates
/// the bit-Lagrange of the all-zero `merged_prefix_sum` at the real
/// `ζ_sumcheck` (no padding required on the verifier side).
pub fn lagrange_eval_at_zero_merged<EF: Field>(zeta_sumcheck: &[EF]) -> EF {
    zeta_sumcheck.iter().fold(EF::one(), |acc, z| acc * (EF::one() - *z))
}

/// Build the `K × 2^c` bit-MLE for the two-stage prover.
///
/// Layout matches `simple_two_stage_eq_product_sumcheck`'s expected
/// `Mle<F, CpuBackend>`: `K` "polynomials" (rows = factor index), each over
/// `c` variables. The Mle storage is row-major as
/// `mle[i * K + k]`, so `(col=i, bit_k=k)` lives at offset `i * K + k`.
///
/// Padding: cols `i ≥ num_real_pairs` and bit positions `k ≥ K_actual` are
/// filled with zeros. `K_actual` is `2 * PREFIX_SUM_BITS = K` here since
/// every prefix sum is padded to `PREFIX_SUM_BITS` bits — so only the col
/// padding is visible.
///
/// `merged_prefix_sum[col]` interleaves `prefix_sums[col]` (taking even bit
/// positions) and `prefix_sums[col+1]` (odd positions), matching
/// `interleave_prefix_sums` in [`crate::poly`].
///
/// Verifier-side analogue is [`build_merged_bit_mle_from_points`] — same
/// layout, but takes already-bit-decomposed `Point<F>`s instead of raw
/// integers.
pub fn build_merged_bit_mle<F: Field>(
    prefix_sums: &[usize],
    log_num_cols: usize,
) -> Mle<F, CpuBackend> {
    let num_real_pairs = prefix_sums.len() - 1;
    let two_c = 1usize << log_num_cols;
    assert!(num_real_pairs <= two_c, "num_real_pairs > 2^c");

    // Flat row-major buffer of length 2^c * K. Padded entries stay zero by
    // virtue of the initial allocation.
    let mut buf = vec![F::zero(); two_c * K];

    buf.par_chunks_mut(K).enumerate().take(num_real_pairs).for_each(|(col, row)| {
        let curr = prefix_sums[col];
        let next = prefix_sums[col + 1];
        // Per `interleave_prefix_sums` (slop_jagged::poly): the interleaved
        // point places `prefix_sum` bit `b` at index `2 * (PREFIX_SUM_BITS - 1 - b) + 1`
        // and `next_prefix_sum` bit `b` at index `2 * (PREFIX_SUM_BITS - 1 - b)`.
        // The two-stage GKR's `k` indexes bits in the same order the
        // verifier-side `full_lagrange_eval` walks them, so we mirror that
        // layout here — see the assertion in the round-trip test.
        for b in 0..PREFIX_SUM_BITS {
            let curr_bit = (curr >> b) & 1;
            let next_bit = (next >> b) & 1;
            let curr_k = 2 * (PREFIX_SUM_BITS - 1 - b) + 1;
            let next_k = 2 * (PREFIX_SUM_BITS - 1 - b);
            if curr_bit == 1 {
                row[curr_k] = F::one();
            }
            if next_bit == 1 {
                row[next_k] = F::one();
            }
        }
    });

    // Mle layout: `[num_non_zero_entries=height, num_polynomials=K]` per
    // `MleBaseBackend::num_polynomials = sizes()[1]`. Storage is row-major
    // as `mle[col * K + k]`, which matches the `buf[col*K+k]` we built above.
    let dimensions = slop_tensor::Dimensions::try_from([two_c, K]).unwrap();
    Mle::new(Tensor { storage: slop_alloc::Buffer::from(buf), dimensions })
}

/// Same data as [`build_merged_bit_mle`] but transposed for the GPU
/// `TaskScope` layout convention (`mle[k * height + col]` — `K` outer,
/// `height` inner). Returns a flat `Vec<F>` of length `K * 2^c` ready to
/// upload via `DeviceBuffer::from_host` and wrap in a
/// `Mle<F, TaskScope>` with `Dimensions::try_from([K, two_c])`.
pub fn build_merged_bit_mle_flat_gpu_layout<F: Field>(
    prefix_sums: &[usize],
    log_num_cols: usize,
) -> Vec<F> {
    let num_real_pairs = prefix_sums.len() - 1;
    let two_c = 1usize << log_num_cols;
    assert!(num_real_pairs <= two_c, "num_real_pairs > 2^c");

    // [K, height] layout: bit `k` block is `[k * two_c .. (k + 1) * two_c)`.
    let mut buf = vec![F::zero(); K * two_c];

    // Parallelize over bit rows (k). For each k, decide whether it pulls from
    // `curr` or `next` and at which bit position; then scan all real cols.
    // Padded cols and padded bit positions both leave their cells at zero.
    buf.par_chunks_mut(two_c).enumerate().for_each(|(k, slice)| {
        // Inverse of the layout in `build_merged_bit_mle`:
        //   k_idx for curr bit b = 2 * (PREFIX_SUM_BITS - 1 - b) + 1
        //   k_idx for next bit b = 2 * (PREFIX_SUM_BITS - 1 - b)
        // So k odd => curr, k even => next; bit b = PREFIX_SUM_BITS - 1 - (k / 2).
        let b = PREFIX_SUM_BITS - 1 - (k / 2);
        let is_curr = k & 1 == 1;
        for col in 0..num_real_pairs {
            let src = if is_curr { prefix_sums[col] } else { prefix_sums[col + 1] };
            if (src >> b) & 1 == 1 {
                slice[col] = F::one();
            }
        }
    });

    buf
}

/// Verifier-side analogue of [`build_merged_bit_mle`]: same K=64 layout, but
/// reads bits from pre-decomposed `Point<F>`s (one per prefix sum,
/// `prefix_sum_length` = `Point::dimension()` bits each, big-endian).
///
/// `col_prefix_sums.len()` = `num_real_pairs + 1`. Pads with zeros at HIGH
/// indices `[K_actual..K)` (= padded MSB bit positions) and at column
/// indices `[num_real_pairs..2^c)`.
pub fn build_merged_bit_mle_from_points<F: Field>(
    col_prefix_sums: &[Point<F>],
    log_num_cols: usize,
) -> Mle<F, CpuBackend> {
    assert!(!col_prefix_sums.is_empty(), "col_prefix_sums must be non-empty");
    let num_real_pairs = col_prefix_sums.len() - 1;
    let prefix_sum_length = col_prefix_sums[0].dimension();
    let two_c = 1usize << log_num_cols;
    assert!(num_real_pairs <= two_c, "num_real_pairs > 2^c");
    assert!(prefix_sum_length <= PREFIX_SUM_BITS, "prefix_sum_length > PREFIX_SUM_BITS");

    let mut buf = vec![F::zero(); two_c * K];

    buf.par_chunks_mut(K).enumerate().take(num_real_pairs).for_each(|(col, row)| {
        let curr_pt = &col_prefix_sums[col];
        let next_pt = &col_prefix_sums[col + 1];
        // Point::from_usize stores bit `b` (b=0 = LSB) at index
        // `dim - 1 - b`. We mirror the same merged layout as the
        // `usize` variant above.
        for b in 0..prefix_sum_length {
            let pt_idx = prefix_sum_length - 1 - b;
            // `Point<F>` indexes to `Init<F, CpuBackend>` which derefs to `F`.
            let curr_bit: F = *curr_pt[pt_idx];
            let next_bit: F = *next_pt[pt_idx];
            let curr_k = 2 * (PREFIX_SUM_BITS - 1 - b) + 1;
            let next_k = 2 * (PREFIX_SUM_BITS - 1 - b);
            row[curr_k] = curr_bit;
            row[next_k] = next_bit;
        }
    });

    let dimensions = slop_tensor::Dimensions::try_from([two_c, K]).unwrap();
    Mle::new(Tensor { storage: slop_alloc::Buffer::from(buf), dimensions })
}

/// Zero-pad `zeta_sumcheck` (length `K_actual`) to length `K` for the
/// two-stage GKR.
///
/// **Layout:** `merged_prefix_sum` is stored big-endian (MSB at index 0) in
/// each Point — so padding `prefix_sum_length` from `K_actual / 2` up to
/// `PREFIX_SUM_BITS = K / 2` inserts the padded MSB bits at the LOW
/// indices `[0..K - K_actual)`. The real `ζ_sumcheck` therefore lands at
/// the HIGH indices `[K - K_actual..K)`. Combined with `p_k = 0` at the
/// matching low-index bit-MLE rows, each padded factor `eq(0, 0) = 1`.
pub fn zeta_padded<EF: Field>(zeta_sumcheck: &[EF]) -> Vec<EF> {
    assert!(zeta_sumcheck.len() <= K, "ζ_sumcheck longer than K = {K}");
    let mut out = vec![EF::zero(); K];
    let offset = K - zeta_sumcheck.len();
    out[offset..].copy_from_slice(zeta_sumcheck);
    out
}

/// Run the two-stage GKR replacement on the CPU prover side.
///
/// `real_sum` is the `Σ_{real col} z_col_eq · L(merged[col], ζ)` value the
/// prover computes from its inner sumcheck's `point_and_eval.1` divided
/// out by the BP eval — i.e. exactly the value the old verifier loop
/// produced. Supplying it lets the prover skip an extra O(num_real_pairs · K)
/// pass over the prefix sums.
///
/// The returned proof's `stage1.claimed_sum` equals
/// `real_sum + L(0, ζ_sumcheck) · (1 − sum_z_first_n)` — the full-hypercube
/// sum (over the padded `2^c` column hypercube) that the verifier will
/// re-derive as the entry point into the two-stage transcripts.
pub fn prove_jagged_eval_two_stage<F, EF, Chal>(
    prefix_sums: &[usize],
    z_col: &[EF],
    zeta_sumcheck: &[EF],
    real_sum: EF,
    challenger: &mut Chal,
) -> TwoStageEqProductProof<EF>
where
    F: Field + 'static,
    EF: ExtensionField<F> + Send + Sync,
    Chal: FieldChallenger<F>,
{
    let log_num_cols = z_col.len();
    let num_real_pairs = prefix_sums.len() - 1;

    let bit_mle = build_merged_bit_mle::<F>(prefix_sums, log_num_cols);

    // Padded col contribution: `L(0, ζ) · (1 − sum_z_first_n)`.
    let l_zero = lagrange_eval_at_zero_merged(zeta_sumcheck);
    let sum_z_first_n = crate::jagged_assist::geq::sum_z_first_n_via_geq::<F, EF>(
        num_real_pairs,
        &z_col.to_vec().into(),
    );
    let padded_contribution = l_zero * (EF::one() - sum_z_first_n);

    let full_hypercube_sum = real_sum + padded_contribution;

    let zeta_padded_vec = zeta_padded(zeta_sumcheck);
    simple_two_stage_eq_product_sumcheck::<F, EF, Chal>(
        bit_mle,
        z_col.to_vec(),
        zeta_padded_vec,
        K1,
        K2,
        full_hypercube_sum,
        challenger,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, Rng};
    use slop_algebra::{extension::BinomialExtensionField, AbstractExtensionField, AbstractField};
    use slop_baby_bear::BabyBear;
    use slop_multilinear::{Mle, Point};

    type F = BabyBear;
    type EF = BinomialExtensionField<BabyBear, 4>;

    /// For every real col, the two-stage inner product `∏_k eq(ζ_padded[k], p_k[col])`
    /// must equal the verifier's per-col `L(merged[col], ζ_sumcheck)`. This catches
    /// any bit-ordering / padding mismatch between `build_merged_bit_mle` and
    /// `interleave_prefix_sums + full_lagrange_eval`.
    #[test]
    fn bit_mle_inner_product_matches_full_lagrange_eval() {
        let mut rng = thread_rng();
        let row_counts: [usize; 6] = [12, 1, 0, 0, 17, 0];
        let mut prefix_sums = row_counts
            .iter()
            .scan(0usize, |state, c| {
                let out = *state;
                *state += c;
                Some(out)
            })
            .collect::<Vec<_>>();
        prefix_sums.push(*prefix_sums.last().unwrap() + row_counts.last().unwrap());
        let num_real_pairs = prefix_sums.len() - 1;
        let log_num_cols = num_real_pairs.next_power_of_two().trailing_zeros() as usize;
        let prefix_sum_length = slop_utils::log2_ceil_usize(*prefix_sums.last().unwrap()) + 1;
        let k_actual = 2 * prefix_sum_length;

        // Random ζ_sumcheck (K_actual-dim) — what the inner sumcheck would produce.
        let zeta_sumcheck: Vec<EF> = (0..k_actual).map(|_| rng.gen::<EF>()).collect();
        let zeta_padded_vec = zeta_padded(&zeta_sumcheck);
        assert_eq!(zeta_padded_vec.len(), K);

        let bit_mle = build_merged_bit_mle::<F>(&prefix_sums, log_num_cols);
        let bit_slice = bit_mle.guts().as_slice();

        for col in 0..num_real_pairs {
            // Two-stage inner product over all K factors.
            let row = &bit_slice[col * K..(col + 1) * K];
            let mut two_stage_inner = EF::one();
            for k in 0..K {
                let zk = zeta_padded_vec[k];
                let pk = EF::from_base(row[k]);
                two_stage_inner *= (EF::one() - zk) * (EF::one() - pk) + zk * pk;
            }

            // Verifier's L(merged[col], ζ_sumcheck).
            let curr_pt: Point<F> = Point::from_usize(prefix_sums[col], prefix_sum_length);
            let next_pt: Point<F> = Point::from_usize(prefix_sums[col + 1], prefix_sum_length);
            let merged = crate::interleave_prefix_sums(&curr_pt, &next_pt);
            let zeta_pt: Point<EF> = zeta_sumcheck.clone().into();
            let l_val = Mle::full_lagrange_eval(&merged, &zeta_pt);

            assert_eq!(
                two_stage_inner, l_val,
                "col={col}: two-stage inner product != L(merged, ζ_sumcheck)",
            );
        }
    }

    /// GPU-layout helper produces the same data as the CPU layout, just transposed.
    #[test]
    fn gpu_layout_matches_cpu_transposed() {
        let prefix_sums: Vec<usize> = vec![0, 12, 13, 13, 13, 30, 30];
        let num_real_pairs = prefix_sums.len() - 1;
        let log_num_cols = num_real_pairs.next_power_of_two().trailing_zeros() as usize;
        let two_c = 1usize << log_num_cols;

        let cpu_mle = build_merged_bit_mle::<F>(&prefix_sums, log_num_cols);
        let cpu_slice = cpu_mle.guts().as_slice();
        let gpu_flat = build_merged_bit_mle_flat_gpu_layout::<F>(&prefix_sums, log_num_cols);

        for col in 0..two_c {
            for k in 0..K {
                let cpu_val = cpu_slice[col * K + k];
                let gpu_val = gpu_flat[k * two_c + col];
                assert_eq!(cpu_val, gpu_val, "(col={col}, k={k}) cpu={cpu_val:?} gpu={gpu_val:?}");
            }
        }
    }

    /// Padded col contribution: for `col ≥ num_real_pairs`, the bit MLE row is
    /// all zeros, so the inner product reduces to `∏_k eq(0, ζ_padded[k])`. The
    /// closed-form helper `lagrange_eval_at_zero_merged` must match this.
    #[test]
    fn padded_col_inner_product_matches_closed_form() {
        let mut rng = thread_rng();
        let zeta_sumcheck: Vec<EF> = (0..10).map(|_| rng.gen::<EF>()).collect();
        let zeta_padded_vec = zeta_padded(&zeta_sumcheck);

        let mut full_product = EF::one();
        for &z in zeta_padded_vec.iter() {
            full_product *= EF::one() - z;
        }
        assert_eq!(full_product, lagrange_eval_at_zero_merged(&zeta_sumcheck));
    }

    /// Round-trip: run `prove_jagged_eval_two_stage`, then check that the
    /// claimed full-hypercube sum equals `real_sum + padded_contribution`
    /// (the verifier-side reconstruction).
    #[test]
    fn two_stage_proof_claim_matches_reconstructed_sum() {
        use slop_baby_bear::baby_bear_poseidon2::{my_bb_16_perm, Perm};
        use slop_challenger::DuplexChallenger;
        use slop_multilinear::partial_lagrange;

        type Challenger = DuplexChallenger<BabyBear, Perm, 16, 8>;

        let mut rng = thread_rng();
        let row_counts: [usize; 6] = [12, 1, 0, 0, 17, 0];
        let mut prefix_sums = row_counts
            .iter()
            .scan(0usize, |state, c| {
                let out = *state;
                *state += c;
                Some(out)
            })
            .collect::<Vec<_>>();
        prefix_sums.push(*prefix_sums.last().unwrap() + row_counts.last().unwrap());
        let num_real_pairs = prefix_sums.len() - 1;
        let log_num_cols = num_real_pairs.next_power_of_two().trailing_zeros() as usize;
        let prefix_sum_length = slop_utils::log2_ceil_usize(*prefix_sums.last().unwrap()) + 1;
        let k_actual = 2 * prefix_sum_length;

        let z_col: Vec<EF> = (0..log_num_cols).map(|_| rng.gen::<EF>()).collect();
        let zeta_sumcheck: Vec<EF> = (0..k_actual).map(|_| rng.gen::<EF>()).collect();

        // Reference real_sum = Σ_{col < num_real_pairs} z_col_eq[col] · L(merged[col], ζ).
        let z_col_partial = partial_lagrange::<EF>(&z_col.clone().into());
        let z_col_lagrange = z_col_partial.as_slice();
        let zeta_pt: Point<EF> = zeta_sumcheck.clone().into();
        let real_sum: EF = (0..num_real_pairs)
            .map(|col| {
                let curr_pt: Point<F> = Point::from_usize(prefix_sums[col], prefix_sum_length);
                let next_pt: Point<F> = Point::from_usize(prefix_sums[col + 1], prefix_sum_length);
                let merged = crate::interleave_prefix_sums(&curr_pt, &next_pt);
                z_col_lagrange[col] * Mle::full_lagrange_eval(&merged, &zeta_pt)
            })
            .sum();

        // Closed-form padded contribution.
        let sum_z_first_n = crate::jagged_assist::geq::sum_z_first_n_via_geq::<F, EF>(
            num_real_pairs,
            &z_col.clone().into(),
        );
        let padded = lagrange_eval_at_zero_merged(&zeta_sumcheck) * (EF::one() - sum_z_first_n);

        // Independently verifiable: full_hypercube_sum should also equal the
        // boolean sum `Σ_{col<2^c} z_col_eq[col] · L(merged_padded[col], ζ)`
        // where padded cols use merged = 0.
        let expected_full = real_sum + padded;

        let mut challenger = Challenger::new(my_bb_16_perm());
        let two_stage = prove_jagged_eval_two_stage::<F, EF, _>(
            &prefix_sums,
            &z_col,
            &zeta_sumcheck,
            real_sum,
            &mut challenger,
        );

        assert_eq!(
            two_stage.stage1.claimed_sum, expected_full,
            "two-stage stage1 claimed_sum != reconstructed full-hypercube sum",
        );
    }
}
