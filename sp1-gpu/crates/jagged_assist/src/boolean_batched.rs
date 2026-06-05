//! GPU-side prover for the booleanity-batched sumcheck.  Mirrors the CPU
//! `slop_jagged::prove_boolean_batched` byte-for-byte so the CPU verifier
//! accepts.
//!
//! Round structure follows the existing `jagged_sumcheck` model:
//! - one `sum-as-poly` kernel computes the 4 evals of the degree-3 round
//!   univariate; host interpolates, observes coefficients, samples ρ.
//! - `DeviceMle::fix_last_variable_constant_padding` (with `padding =
//!   Ext::zero()`) folds the three logical tables (`inc`, `eq`, the
//!   `[32, ·]` p_b stack) — 3 kernel launches per round.
//!
//! All EF/Felt conversion happens once up-front via the
//! `boolean_curr_bits_ext` kernel that promotes the 32 curr-bit MLEs to
//! `ext_t` (Boolean → 0/1 ext).  Subsequent rounds operate purely on
//! extension tables.

use slop_algebra::{interpolate_univariate_polynomial, AbstractField, Field, UnivariatePolynomial};
use slop_alloc::Buffer;
use slop_challenger::{FieldChallenger, VariableLengthChallenger};
use slop_jagged::{BooleanityBatchedProof, LOG_NUM_BITS};
use slop_multilinear::{Mle, Point};
use slop_sumcheck::PartialSumcheckProof;
use slop_tensor::Tensor;
use sp1_gpu_cudart::sys::v2_kernels::{
    boolean_curr_bits_ext_kernel, boolean_inc_table_kernel, boolean_sum_as_poly_half_kernel,
};
use sp1_gpu_cudart::{args, DeviceBuffer, DeviceMle, DevicePoint, DeviceTensor, TaskScope};
use sp1_gpu_utils::{Ext, Felt};

const NUM_BITS: usize = 32;

/// Prove the booleanity-batched sumcheck on GPU.
///
/// Inputs:
/// - `z_eta`: the two-stage GKR's `stage2.point_and_eval.0`, length `c`.
/// - `prefix_sums`: host slice of `num_real_cols + 1` prefix sums (last
///   entry = max prefix sum).
/// - `log_num_cols`: `c`, the column-cube bit width.
/// - `v_curr`, `v_next`: 32 ext-field evaluation claims, one per bit
///   (LSB-first index `b = 0..32`).
/// - `alpha`: per-bit batching scalar for the 3 claims (shift + booleanity
///   + curr-eval).
/// - `rho_bit`: 5-dim bit-side RLC point; cross-bit weights are
///   `eq(rho_bit, b)` for `b = 0..NUM_BITS`.
/// - `challenger`: host challenger; observed coeffs + sampled ρ each round.
/// - `backend`: GPU task scope.
///
/// Returns a `BooleanityBatchedProof<Ext>` byte-identical to the CPU
/// implementation.
#[allow(clippy::too_many_arguments)]
pub fn prove_boolean_batched_gpu<Chal>(
    z_eta: &Point<Ext>,
    prefix_sums: &[usize],
    log_num_cols: usize,
    v_curr: &[Ext],
    v_next: &[Ext],
    alpha: Ext,
    rho_bit: &Point<Ext>,
    challenger: &mut Chal,
    backend: &TaskScope,
) -> BooleanityBatchedProof<Ext>
where
    Chal: FieldChallenger<Felt>,
{
    assert_eq!(z_eta.dimension(), log_num_cols);
    assert_eq!(v_curr.len(), NUM_BITS);
    assert_eq!(v_next.len(), NUM_BITS);
    assert_eq!(rho_bit.dimension(), LOG_NUM_BITS);

    let c = log_num_cols;
    let two_c = 1usize << c;
    let num_real_cols = prefix_sums.len() - 1;
    let max_prefix_sum = *prefix_sums.last().unwrap();
    assert!(num_real_cols <= two_c, "num_real_cols > 2^c");

    // ---- Host-side setup: λ_b, eq(ρ_bit, b), initial claim. ----
    let lambda: Vec<Ext> = (0..NUM_BITS)
        .map(|b| if (max_prefix_sum >> b) & 1 == 1 { Ext::one() } else { Ext::zero() })
        .collect();
    let eq_rho: Vec<Ext> = bit_rlc_table(rho_bit);

    // eq(z_eta, num_real_cols − 1) — single full_lagrange_eval, host-cheap.
    let boundary: Point<Felt> = Point::from_usize(num_real_cols - 1, c);
    let eq_at_boundary: Ext = Mle::full_lagrange_eval(&boundary, z_eta);

    let alpha_sq = alpha * alpha;
    // Split the initial claim into the two summands.  Both are determined
    // from the protocol's algebra (the verifier can compute these too):
    //   - T1 (= Σ_j inc(z, j)·q(j)): expansion of `Σ_j inc · Σ_b eq(ρ,b) p_b`
    //     = Σ_b eq(ρ,b) · (p_{next,b}(z) − λ_b · eq(z, num_real_cols−1)).
    //   - T2 (= Σ_j eq(z, j)·(α·Q + (α²−α)·q)): for Boolean p, p² = p so
    //     Σ_j eq·p² = Σ_j eq·p = v_curr_b ⇒ T2_claim = Σ_b eq(ρ,b) · α² · v_curr_b.
    let mut claim_t1: Ext =
        (0..NUM_BITS).map(|b| eq_rho[b] * (v_next[b] - lambda[b] * eq_at_boundary)).sum();
    let mut claim_t2: Ext = alpha_sq * (0..NUM_BITS).map(|b| eq_rho[b] * v_curr[b]).sum::<Ext>();
    let initial_claim: Ext = claim_t1 + claim_t2;

    // ---- Upload static device buffers. ----
    let z_eta_host: Vec<Ext> = z_eta.iter().copied().collect();
    let z_eta_dev_buf = upload_ext_slice(&z_eta_host, backend);
    let eq_rho_dev = upload_ext_slice(&eq_rho, backend);

    // Prefix sums as u32 for the device kernels.
    let prefix_sums_u32: Vec<u32> = prefix_sums.iter().map(|&s| s as u32).collect();
    let prefix_sums_buf: Buffer<u32> = prefix_sums_u32.into();
    let prefix_sums_dev: Buffer<u32, TaskScope> =
        DeviceBuffer::from_host(&prefix_sums_buf, backend).unwrap().into_inner();

    // ---- Build initial device tables: inc, eq, and 32 curr-bit MLEs. ----
    // `inc` and `eq` are `[1, 2^c]` MLEs; `p_curr` is `[32, 2^c]`.
    let inc_buf = build_inc_table(&z_eta_dev_buf, c, num_real_cols, backend);
    let inc_curr_mle: DeviceMle<Ext> = DeviceMle::from(inc_buf);

    let z_eta_point = Point::new(z_eta_dev_buf);
    let z_eta_dpoint = DevicePoint::new(z_eta_point);
    let eq_curr_mle: DeviceMle<Ext> = z_eta_dpoint.partial_lagrange();

    let p_curr_buf = build_curr_bits_ext(&prefix_sums_dev, num_real_cols as u32, two_c, backend);
    let p_curr_tensor = Tensor::from(p_curr_buf).reshape([NUM_BITS, two_c]);
    let p_curr_mle: DeviceMle<Ext> = DeviceMle::from(p_curr_tensor);

    // ---- Sumcheck rounds. ----
    // The kernel only emits 4 accumulators per round: G_T1(0), G_T1(1/2),
    // G_T2(0), G_T2(1/2).  We deduce G_T1(1) and G_T2(1) from the tracked
    // `claim_t1`, `claim_t2` (prev-round claim trick), then reconstruct the
    // degree-3 combined polynomial using Gruen's eq-factor structure on T2:
    //
    //   G_T2(t) = eq(z_round, t) · K(t),   K degree-2.
    //
    // With G_T2 at 3 points (0, 1/2, 1) ⇒ K at 3 points ⇒ K interpolated
    // ⇒ G_T2 monomial; sum with G_T1 monomial → combined degree-3 G in
    // the same wire format as the verifier expects.
    let half_inv: Ext = Ext::two().inverse();

    let mut univariate_polys: Vec<UnivariatePolynomial<Ext>> = Vec::with_capacity(c);
    let mut point: Vec<Ext> = Vec::with_capacity(c);

    let mut inc_curr = inc_curr_mle;
    let mut eq_curr = eq_curr_mle;
    let mut p_curr = p_curr_mle;
    let mut half: usize = two_c / 2;

    for r in 0..c {
        // 1. sum-as-poly: 4 accumulators (G_T1(0), G_T1(1/2), G_T2(0), G_T2(1/2)).
        let (g_t1_0, g_t1_half, g_t2_0, g_t2_half) = sum_as_poly_round_half(
            &inc_curr,
            &eq_curr,
            &p_curr,
            &eq_rho_dev,
            alpha,
            half_inv,
            half,
            backend,
        );

        // 2. host-side reconstruction.  z_round at round `r` is z_eta[c-1-r]
        // (Point convention: index 0 = MSB, index c-1 = LSB; round 0 folds
        // the LSB / last variable).
        let z_round: Ext = *z_eta[c - 1 - r];
        let g_t1_1 = claim_t1 - g_t1_0;
        let g_t2_1 = claim_t2 - g_t2_0;

        debug_assert_eq!(
            g_t1_0 + g_t2_0 + g_t1_1 + g_t2_1,
            claim_t1 + claim_t2,
            "G(0) + G(1) ≠ combined claim",
        );

        // G_T1 (degree-2): interpolate from (0, 1, 1/2).
        let g_t1_poly = interpolate_univariate_polynomial(
            &[Ext::zero(), Ext::one(), half_inv],
            &[g_t1_0, g_t1_1, g_t1_half],
        );

        // G_T2: K(t) = G_T2(t) / eq(z_round, t).  eq(z_round, 0) = 1 − z,
        // eq(z_round, 1) = z, eq(z_round, 1/2) = 1/2 (always).
        let one_minus_z = Ext::one() - z_round;
        let k_0 = g_t2_0 * one_minus_z.inverse();
        let k_1 = g_t2_1 * z_round.inverse();
        let k_half = g_t2_half * Ext::two();
        let k_poly = interpolate_univariate_polynomial(
            &[Ext::zero(), Ext::one(), half_inv],
            &[k_0, k_1, k_half],
        );

        // eq(z_round, t) = (1 − z)(1 − t) + z·t = (1 − z) + (2z − 1)·t.
        // Verify: eq(0) = 1 − z, eq(1) = z, eq(1/2) = 1/2. ✓
        let two_z_minus_one = z_round + z_round - Ext::one();
        let eq_round_poly = UnivariatePolynomial::new(vec![one_minus_z, two_z_minus_one]);
        // G_T2(t) = eq_round(t) · K(t)   — degree 3.
        let g_t2_poly = eq_round_poly * k_poly;

        // Combined G(t) = G_T1(t) + G_T2(t), padded to the degree-3 wire
        // shape (verifier asserts `coefficients.len() == expected_degree + 1`).
        // Clone here because we re-evaluate both summands at ρ below to refresh
        // the per-summand claim trackers for the next round.
        let uni_poly = (g_t1_poly.clone() + g_t2_poly.clone()).pad_to(4);
        debug_assert_eq!(
            uni_poly.eval_at_point(Ext::zero()) + uni_poly.eval_at_point(Ext::one()),
            claim_t1 + claim_t2,
            "uni_poly(0) + uni_poly(1) ≠ combined claim",
        );

        // 3. FS: observe + sample.  Update both sub-claims with G_T1(ρ),
        // G_T2(ρ) before folding the tables — we need them for the *next*
        // round's `prev-round claim` trick.
        challenger.observe_constant_length_extension_slice(&uni_poly.coefficients);
        univariate_polys.push(uni_poly);

        let rho: Ext = challenger.sample_ext_element();
        point.insert(0, rho);
        claim_t1 = g_t1_poly.eval_at_point(rho);
        claim_t2 = g_t2_poly.eval_at_point(rho);

        // 4. fix-last-variable on the three logical tables (3 launches).
        inc_curr = inc_curr.fix_last_variable_constant_padding(rho, Ext::zero());
        eq_curr = eq_curr.fix_last_variable_constant_padding(rho, Ext::zero());
        p_curr = p_curr.fix_last_variable_constant_padding(rho, Ext::zero());
        half /= 2;
    }

    let running_claim = claim_t1 + claim_t2;

    // ---- Read 32 final `p_b(z_new)` from device. ----
    // After c folds, `p_curr` has shape `[32, 1]`; the underlying buffer is
    // 32 contiguous Ext values.
    let final_evals_host: Vec<Ext> = {
        let mle: Tensor<Ext> = p_curr.into_guts().to_host().unwrap();
        mle.into_buffer().into_vec()
    };
    let final_evals: Vec<Ext> = final_evals_host[..NUM_BITS].to_vec();

    BooleanityBatchedProof {
        partial_sumcheck_proof: PartialSumcheckProof {
            univariate_polys,
            claimed_sum: initial_claim,
            point_and_eval: (Point::from(point), running_claim),
        },
        final_evals,
    }
}

// ---------- internal helpers ----------

/// `[eq(rho_bit, b)]_{b = 0..NUM_BITS}` — the cross-bit RLC weights.  Built
/// host-side via `Mle::blocking_partial_lagrange`; result is the same length-32
/// table the CPU prover uses.
fn bit_rlc_table(rho_bit: &Point<Ext>) -> Vec<Ext> {
    debug_assert_eq!(rho_bit.dimension(), LOG_NUM_BITS);
    Mle::blocking_partial_lagrange(rho_bit).guts().as_slice().to_vec()
}

fn upload_ext_slice(s: &[Ext], backend: &TaskScope) -> Buffer<Ext, TaskScope> {
    let buf: Buffer<Ext> = s.to_vec().into();
    DeviceBuffer::from_host(&buf, backend).unwrap().into_inner()
}

/// Allocate + launch the `boolean_inc_table` kernel; returns a `[2^c]`
/// device buffer of `inc(z_eta, j)` values.
fn build_inc_table(
    z_eta_dev: &Buffer<Ext, TaskScope>,
    c: usize,
    num_real_cols: usize,
    backend: &TaskScope,
) -> Buffer<Ext, TaskScope> {
    let two_c = 1usize << c;
    let mut out: Buffer<Ext, TaskScope> = Buffer::with_capacity_in(two_c, backend.clone());
    unsafe { out.set_len(two_c) };

    const BLOCK_SIZE: usize = 128;
    let grid_x = two_c.div_ceil(BLOCK_SIZE);
    let threshold = (num_real_cols - 1) as u32;

    unsafe {
        let kernel = boolean_inc_table_kernel();
        let kargs = args!(z_eta_dev.as_ptr(), c as u32, threshold, two_c as u32, out.as_mut_ptr());
        backend.launch_kernel(kernel, (grid_x, 1, 1), (BLOCK_SIZE, 1, 1), &kargs, 0).unwrap();
    }
    out
}

/// Launch `boolean_curr_bits_ext` to build the `[32, 2^c]` Ext curr-bit
/// MLE buffer on device.  Returned buffer is row-major: row `b` starts at
/// offset `b · 2^c`.
fn build_curr_bits_ext(
    prefix_sums_dev: &Buffer<u32, TaskScope>,
    num_real_cols: u32,
    two_c: usize,
    backend: &TaskScope,
) -> Buffer<Ext, TaskScope> {
    let total = NUM_BITS * two_c;
    let mut out: Buffer<Ext, TaskScope> = Buffer::with_capacity_in(total, backend.clone());
    unsafe { out.set_len(total) };

    const BLOCK_X: usize = 32;
    const BLOCK_Y: usize = 4;
    let grid_x = two_c.div_ceil(BLOCK_X);
    let grid_y = NUM_BITS.div_ceil(BLOCK_Y);

    unsafe {
        let kernel = boolean_curr_bits_ext_kernel();
        let kargs = args!(prefix_sums_dev.as_ptr(), num_real_cols, two_c as u32, out.as_mut_ptr());
        backend
            .launch_kernel(kernel, (grid_x, grid_y, 1), (BLOCK_X, BLOCK_Y, 1), &kargs, 0)
            .unwrap();
    }
    out
}

/// One round of the **reduced-register** `sum-as-poly`: launches the
/// `boolean_sum_as_poly_half_kernel`, sums block partials on host, returns
/// `(G_T1(0), G_T1(1/2), G_T2(0), G_T2(1/2))`.
#[allow(clippy::too_many_arguments)]
fn sum_as_poly_round_half(
    inc_mle: &DeviceMle<Ext>,
    eq_mle: &DeviceMle<Ext>,
    p_mle: &DeviceMle<Ext>,
    eq_rho_dev: &Buffer<Ext, TaskScope>,
    alpha: Ext,
    half_inv: Ext,
    half: usize,
    backend: &TaskScope,
) -> (Ext, Ext, Ext, Ext) {
    const BLOCK_SIZE: usize = 128;
    let grid_x = half.div_ceil(BLOCK_SIZE);

    let mut block_partial: Buffer<Ext, TaskScope> =
        Buffer::with_capacity_in(4 * grid_x, backend.clone());
    unsafe { block_partial.set_len(4 * grid_x) };

    // `BLOCK_SIZE / 32` Ext scratch for the warp-tile shared array.
    let shared_mem = (BLOCK_SIZE / 32).max(1) * std::mem::size_of::<Ext>();

    unsafe {
        let kernel = boolean_sum_as_poly_half_kernel();
        let kargs = args!(
            inc_mle.guts().as_ptr(),
            eq_mle.guts().as_ptr(),
            p_mle.guts().as_ptr(),
            eq_rho_dev.as_ptr(),
            alpha,
            half_inv,
            half as u32,
            block_partial.as_mut_ptr()
        );
        backend
            .launch_kernel(kernel, (grid_x, 1, 1), (BLOCK_SIZE, 1, 1), &kargs, shared_mem)
            .unwrap();
    }

    let host: Vec<Ext> = DeviceTensor::from_raw(Tensor::from(block_partial))
        .to_host()
        .unwrap()
        .into_buffer()
        .into_vec();
    let (mut t1_0, mut t1_h, mut t2_0, mut t2_h) =
        (Ext::zero(), Ext::zero(), Ext::zero(), Ext::zero());
    for blk in 0..grid_x {
        t1_0 += host[blk * 4];
        t1_h += host[blk * 4 + 1];
        t2_0 += host[blk * 4 + 2];
        t2_h += host[blk * 4 + 3];
    }
    (t1_0, t1_h, t2_0, t2_h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use slop_algebra::AbstractExtensionField;
    use slop_challenger::IopCtx;
    use slop_jagged::{BooleanityBatched, IncBranchingProgram, NUM_BITS, PREFIX_SUM_BITS};
    use slop_multilinear::Mle;
    use sp1_gpu_cudart::run_sync_in_place;
    use sp1_primitives::SP1GlobalContext;

    /// Verify the `boolean_curr_bits_ext` kernel builds a `[32, 2^c]` Ext
    /// buffer matching what the CPU-side construction produces.
    #[test]
    fn test_gpu_curr_bits_matches_cpu() {
        let c = 4usize;
        let two_c = 1usize << c;
        let prefix_sums: Vec<usize> = vec![0, 3, 10, 10, 21, 25, 26, 29, 35, 36, 41, 47, 47, 53];
        let num_real_cols = prefix_sums.len() - 1;

        let ps = prefix_sums.clone();
        let cpu_flat: Vec<Ext> = (0..NUM_BITS)
            .flat_map(|b| {
                let ps = ps.clone();
                (0..two_c).map(move |col| {
                    if col < num_real_cols && ((ps[col] >> b) & 1) == 1 {
                        Ext::one()
                    } else {
                        Ext::zero()
                    }
                })
            })
            .collect();

        let gpu_flat: Vec<Ext> = run_sync_in_place(|backend| {
            let psums_u32: Vec<u32> = prefix_sums.iter().map(|&s| s as u32).collect();
            let psums_buf: Buffer<u32> = psums_u32.into();
            let psums_dev: Buffer<u32, TaskScope> =
                DeviceBuffer::from_host(&psums_buf, &backend).unwrap().into_inner();
            let out = build_curr_bits_ext(&psums_dev, num_real_cols as u32, two_c, &backend);
            DeviceTensor::from_raw(Tensor::from(out)).to_host().unwrap().into_buffer().into_vec()
        })
        .unwrap();

        assert_eq!(cpu_flat.len(), gpu_flat.len());
        for (i, (c_v, g_v)) in cpu_flat.iter().zip(gpu_flat.iter()).enumerate() {
            assert_eq!(c_v, g_v, "curr-bits mismatch at flat index {i}");
        }
    }

    /// `boolean_inc_table_kernel`'s output equals the CPU `IncBranchingProgram::eval`
    /// at all 2^c integer points.
    #[test]
    fn test_gpu_inc_table_matches_cpu() {
        let c = 4usize;
        let two_c = 1usize << c;
        let num_real_cols = 11usize;

        let mut rng = StdRng::seed_from_u64(7);
        let z_eta: Point<Ext> = (0..c).map(|_| rng.gen::<Ext>()).collect();
        let z_host: Vec<Ext> = z_eta.iter().copied().collect();

        let cpu_table: Vec<Ext> = {
            let bp = IncBranchingProgram::new(c, num_real_cols);
            (0..two_c)
                .map(|j| {
                    let j_pt_base: Point<Felt> = Point::from_usize(j, c);
                    let j_pt_ext: Point<Ext> =
                        j_pt_base.iter().map(|&b| Ext::from_base(b)).collect();
                    bp.eval(&z_eta, &j_pt_ext)
                })
                .collect()
        };

        let gpu_table: Vec<Ext> = run_sync_in_place(|backend| {
            let z_dev = upload_ext_slice(&z_host, &backend);
            let buf = build_inc_table(&z_dev, c, num_real_cols, &backend);
            DeviceTensor::from_raw(Tensor::from(buf)).to_host().unwrap().into_buffer().into_vec()
        })
        .unwrap();

        assert_eq!(cpu_table.len(), gpu_table.len());
        for (j, (cpu_v, gpu_v)) in cpu_table.iter().zip(gpu_table.iter()).enumerate() {
            assert_eq!(*cpu_v, *gpu_v, "inc table mismatch at j={j}");
        }
    }

    /// GPU prove + CPU verify roundtrip with the same inputs as CPU
    /// prove + verify; checks both proofs verify and have identical
    /// final-eval claims.
    #[test]
    fn test_gpu_vs_cpu_boolean_batched() {
        let row_counts: Vec<usize> = vec![3, 7, 0, 11, 4, 0, 9, 2, 5, 1, 0, 6];
        let mut prefix_sums: Vec<usize> = row_counts
            .iter()
            .scan(0, |s, r| {
                let v = *s;
                *s += r;
                Some(v)
            })
            .collect();
        prefix_sums.push(*prefix_sums.last().unwrap() + *row_counts.last().unwrap());
        let num_real_cols = prefix_sums.len() - 1;
        let c = num_real_cols.next_power_of_two().max(2).trailing_zeros() as usize;
        let two_c = 1usize << c;

        let curr_bits: Vec<Mle<Felt>> = (0..NUM_BITS)
            .map(|b| {
                let table: Vec<Felt> = (0..two_c)
                    .map(|col| {
                        if col < num_real_cols && ((prefix_sums[col] >> b) & 1) == 1 {
                            Felt::one()
                        } else {
                            Felt::zero()
                        }
                    })
                    .collect();
                Mle::from(table)
            })
            .collect();

        let mut rng = StdRng::seed_from_u64(7);
        let z_eta: Point<Ext> = (0..c).map(|_| rng.gen::<Ext>()).collect();
        let v_curr: Vec<Ext> =
            curr_bits.iter().map(|p| p.blocking_eval_at::<Ext>(&z_eta).to_vec()[0]).collect();
        let v_next: Vec<Ext> = (0..NUM_BITS)
            .map(|b| {
                let table: Vec<Felt> = (0..two_c)
                    .map(|col| {
                        if col < num_real_cols && ((prefix_sums[col + 1] >> b) & 1) == 1 {
                            Felt::one()
                        } else {
                            Felt::zero()
                        }
                    })
                    .collect();
                Mle::from(table).blocking_eval_at::<Ext>(&z_eta).to_vec()[0]
            })
            .collect();

        let mut cpu_ch = SP1GlobalContext::default_challenger();
        let mut gpu_ch = SP1GlobalContext::default_challenger();
        let alpha: Ext = cpu_ch.sample_ext_element();
        let rho_bit_vec: Vec<Ext> =
            (0..LOG_NUM_BITS).map(|_| cpu_ch.sample_ext_element()).collect();
        let rho_bit: Point<Ext> = rho_bit_vec.into();
        let _: Ext = gpu_ch.sample_ext_element();
        for _ in 0..LOG_NUM_BITS {
            let _: Ext = gpu_ch.sample_ext_element();
        }

        let max_prefix_sum = *prefix_sums.last().unwrap();
        let cfg = BooleanityBatched::new(num_real_cols, max_prefix_sum);

        // Interleave (v_next, v_curr) back into the two-stage `final_evals` layout
        // (`final_evals[2(PREFIX_SUM_BITS−1−b)] = v_next[b]`, `+1 = v_curr[b]`).
        let mut two_stage_finals = vec![Ext::zero(); 2 * NUM_BITS];
        for b in 0..NUM_BITS {
            two_stage_finals[2 * (PREFIX_SUM_BITS - 1 - b)] = v_next[b];
            two_stage_finals[2 * (PREFIX_SUM_BITS - 1 - b) + 1] = v_curr[b];
        }

        let cpu_proof = cfg.prove::<Felt, Ext, _>(
            &z_eta,
            &curr_bits,
            &two_stage_finals,
            alpha,
            &rho_bit,
            &mut cpu_ch,
        );

        let gpu_proof = run_sync_in_place(|backend| {
            prove_boolean_batched_gpu(
                &z_eta,
                &prefix_sums,
                c,
                &v_curr,
                &v_next,
                alpha,
                &rho_bit,
                &mut gpu_ch,
                &backend,
            )
        })
        .unwrap();

        let mut cpu_ver = SP1GlobalContext::default_challenger();
        let _: Ext = cpu_ver.sample_ext_element();
        for _ in 0..LOG_NUM_BITS {
            let _: Ext = cpu_ver.sample_ext_element();
        }
        cfg.verify::<Felt, Ext, _>(
            &cpu_proof,
            &z_eta,
            &two_stage_finals,
            alpha,
            &rho_bit,
            &mut cpu_ver,
        )
        .expect("CPU proof must verify");

        let mut gpu_ver = SP1GlobalContext::default_challenger();
        let _: Ext = gpu_ver.sample_ext_element();
        for _ in 0..LOG_NUM_BITS {
            let _: Ext = gpu_ver.sample_ext_element();
        }
        cfg.verify::<Felt, Ext, _>(
            &gpu_proof,
            &z_eta,
            &two_stage_finals,
            alpha,
            &rho_bit,
            &mut gpu_ver,
        )
        .expect("GPU proof must verify");

        assert_eq!(
            cpu_proof.partial_sumcheck_proof.claimed_sum,
            gpu_proof.partial_sumcheck_proof.claimed_sum,
            "claimed sums differ"
        );
        for (i, (cp, gp)) in cpu_proof
            .partial_sumcheck_proof
            .univariate_polys
            .iter()
            .zip(gpu_proof.partial_sumcheck_proof.univariate_polys.iter())
            .enumerate()
        {
            assert_eq!(cp.coefficients, gp.coefficients, "round {i} univariate polys differ");
        }
        assert_eq!(
            cpu_proof.partial_sumcheck_proof.point_and_eval,
            gpu_proof.partial_sumcheck_proof.point_and_eval,
            "point_and_eval differ"
        );
        assert_eq!(cpu_proof.final_evals, gpu_proof.final_evals, "final evals differ");
    }
}
