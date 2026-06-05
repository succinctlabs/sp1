//! Standalone benchmark driver for a degree-K product sumcheck.
//!
//! Given K multilinears A_0, ..., A_{K-1} over n variables (stored as a single MLE of shape
//! `[K, 2^n]`), runs the sumcheck for the claim
//!   sum_{x in {0,1}^n} prod_j A_j(x)
//! producing a [`PartialSumcheckProof`] and the K final evaluations.
//!
//! Round structure:
//! * Round 0 — base-field `sum_as_poly` (no fold yet).
//! * Rounds 1..n-1 — fused `fix_and_sum`: fold by the previous alpha AND compute this round's
//!   univariate in one pass over the data.  Round 1 is base→ext; later rounds are ext→ext.
//! * Final fold — apply the last alpha to extract the K final evaluation claims.
//!
//! Each round's prover message is a degree-K univariate; the kernel evaluates it at the K
//! points t ∈ {0, 2, 3, ..., K}, and the host recovers t = 1 from the round claim.
//!
//! This is intentionally separate from the slop `SumcheckPoly` trait machinery so the
//! benchmarks measure only the raw round work.

use std::sync::OnceLock;

use itertools::Itertools;
use slop_algebra::{AbstractExtensionField, AbstractField, Field, UnivariatePolynomial};
use slop_challenger::FieldChallenger;
use slop_multilinear::{Mle, MleBaseBackend};
use slop_sumcheck::PartialSumcheckProof;
use slop_tensor::Tensor;
use sp1_gpu_cudart::sys::runtime::{Dim3, KernelPtr};
use sp1_gpu_cudart::sys::v2_kernels::{
    mle_fix_last_variable_koala_bear_base_extension_zero_padding,
    mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
    product_sumcheck_fix_and_sum_base_2_kernel, product_sumcheck_fix_and_sum_base_4_kernel,
    product_sumcheck_fix_and_sum_base_8_kernel, product_sumcheck_fix_and_sum_coop_base_16_kernel,
    product_sumcheck_fix_and_sum_coop_base_32_kernel,
    product_sumcheck_fix_and_sum_coop_base_64_kernel,
    product_sumcheck_fix_and_sum_coop_ext_16_kernel,
    product_sumcheck_fix_and_sum_coop_ext_32_kernel,
    product_sumcheck_fix_and_sum_coop_ext_64_kernel, product_sumcheck_fix_and_sum_ext_2_kernel,
    product_sumcheck_fix_and_sum_ext_4_kernel, product_sumcheck_fix_and_sum_ext_8_kernel,
    product_sumcheck_sum_as_poly_base_16_kernel, product_sumcheck_sum_as_poly_base_2_kernel,
    product_sumcheck_sum_as_poly_base_32_kernel, product_sumcheck_sum_as_poly_base_4_kernel,
    product_sumcheck_sum_as_poly_base_64_kernel, product_sumcheck_sum_as_poly_base_8_kernel,
};
use sp1_gpu_cudart::{args, DeviceTensor, TaskScope};
use sp1_gpu_utils::{Ext, Felt};

/// Pick the round-0 (base-field) kernel for a given product width K.
fn base_sum_as_poly_kernel(k: usize) -> unsafe extern "C" fn() -> KernelPtr {
    match k {
        2 => product_sumcheck_sum_as_poly_base_2_kernel,
        4 => product_sumcheck_sum_as_poly_base_4_kernel,
        8 => product_sumcheck_sum_as_poly_base_8_kernel,
        16 => product_sumcheck_sum_as_poly_base_16_kernel,
        32 => product_sumcheck_sum_as_poly_base_32_kernel,
        64 => product_sumcheck_sum_as_poly_base_64_kernel,
        _ => panic!("unsupported product width K={k}"),
    }
}

/// Round 1's fused base→ext fix_and_sum kernel (simple variant, K ∈ {2, 4, 8}).
fn base_fix_and_sum_kernel(k: usize) -> unsafe extern "C" fn() -> KernelPtr {
    match k {
        2 => product_sumcheck_fix_and_sum_base_2_kernel,
        4 => product_sumcheck_fix_and_sum_base_4_kernel,
        8 => product_sumcheck_fix_and_sum_base_8_kernel,
        _ => panic!("simple base fix_and_sum not built for K={k}; use the coop variant"),
    }
}

/// Rounds 2..n-1 fused ext→ext fix_and_sum kernel (simple variant, K ∈ {2, 4, 8}).
fn ext_fix_and_sum_kernel(k: usize) -> unsafe extern "C" fn() -> KernelPtr {
    match k {
        2 => product_sumcheck_fix_and_sum_ext_2_kernel,
        4 => product_sumcheck_fix_and_sum_ext_4_kernel,
        8 => product_sumcheck_fix_and_sum_ext_8_kernel,
        _ => panic!("simple ext fix_and_sum not built for K={k}; use the coop variant"),
    }
}

/// Cooperative-variant base→ext fix_and_sum kernel (K ∈ {16, 32, 64}).
fn base_fix_and_sum_coop_kernel(k: usize) -> unsafe extern "C" fn() -> KernelPtr {
    match k {
        16 => product_sumcheck_fix_and_sum_coop_base_16_kernel,
        32 => product_sumcheck_fix_and_sum_coop_base_32_kernel,
        64 => product_sumcheck_fix_and_sum_coop_base_64_kernel,
        _ => panic!("coop base fix_and_sum not built for K={k}; use the simple variant"),
    }
}

/// Cooperative-variant ext→ext fix_and_sum kernel (K ∈ {16, 32, 64}).
fn ext_fix_and_sum_coop_kernel(k: usize) -> unsafe extern "C" fn() -> KernelPtr {
    match k {
        16 => product_sumcheck_fix_and_sum_coop_ext_16_kernel,
        32 => product_sumcheck_fix_and_sum_coop_ext_32_kernel,
        64 => product_sumcheck_fix_and_sum_coop_ext_64_kernel,
        _ => panic!("coop ext fix_and_sum not built for K={k}; use the simple variant"),
    }
}

/// Use the cooperative kernel when the thread-per-x_top kernel would spill heavily.  For
/// small K the simple kernel has lower control-flow / sync overhead and wins.
fn should_use_coop(k: usize) -> bool {
    k >= 16
}

// Note: keep this consistent with the kernel's per-thread register pressure.
// For larger K the kernel holds K base/ext "running product" registers plus K ext accumulators,
// so we shrink the block size to give the compiler more registers per thread.
fn block_size_for_k(k: usize) -> usize {
    match k {
        2 | 4 | 8 => 256,
        16 => 128,
        32 => 64,
        64 => 32,
        _ => 256,
    }
}

/// Run one round's `sum_as_poly` and interpolate the univariate prover message.
fn sum_as_poly<F>(
    mles: &Mle<F, TaskScope>,
    claim: Ext,
    kernel: unsafe extern "C" fn() -> KernelPtr,
    k: usize,
) -> UnivariatePolynomial<Ext>
where
    F: Field,
{
    let num_variables = mles.num_variables();
    debug_assert!(num_variables >= 1);
    let scope = mles.backend();

    let block_size = block_size_for_k(k);
    let output_height = 1usize << (num_variables - 1);
    let grid_x = output_height.div_ceil(block_size);
    let grid_dim: Dim3 = (grid_x, 1, 1).into();

    // [K, grid_x] partial sums (one row per eval point).
    let mut block_evals = Tensor::<Ext, TaskScope>::with_sizes_in([k, grid_x], scope.clone());

    let num_tiles = block_size.div_ceil(32).max(1);
    let shared_mem = num_tiles * std::mem::size_of::<Ext>();
    let num_variables_minus_one: usize = num_variables as usize - 1;

    unsafe {
        let kargs = args!(block_evals.as_mut_ptr(), mles.guts().as_ptr(), num_variables_minus_one);
        block_evals.assume_init();
        scope.launch_kernel(kernel(), grid_dim, block_size, &kargs, shared_mem).unwrap();
    }

    // Sum partial-sums across blocks → K ext_t evals.
    let block_evals = DeviceTensor::from_raw(block_evals);
    let host_evals = block_evals.sum_dim(1).to_host().unwrap();
    interpolate_from_kernel_evals(host_evals.as_slice(), claim, k)
}

/// Helper that converts a univariate prover-message poly's coefficients into a felt slice and
/// observes them in the challenger transcript.
pub(crate) fn observe_uni<C>(challenger: &mut C, uni: &UnivariatePolynomial<Ext>)
where
    C: FieldChallenger<Felt>,
{
    let coeffs: Vec<Felt> =
        uni.coefficients.iter().flat_map(|x| x.as_base_slice()).copied().collect_vec();
    challenger.observe_slice(&coeffs);
}

/// Build the (K+1) × (K+1) Lagrange-to-power matrix for nodes {0, 1, ..., K}.
///
/// Entry `M[j * n + i]` is the coefficient of x^j in the i-th Lagrange basis polynomial
/// L_i(x) = ∏_{q ≠ i} (x - q) / (i - q).  Given evaluations y_i at the K+1 nodes, the
/// power-form coefficients of the interpolating polynomial are
///   coef[j] = ∑_i M[j * n + i] · y[i].
///
/// All entries live in the base field, so the runtime apply is (K+1)² ext × felt mults — vs
/// O(K³) ext × ext for the generic [`slop_algebra::interpolate_univariate_polynomial`].
pub(crate) fn build_lagrange_matrix(k: usize) -> Vec<Felt> {
    let n = k + 1;
    let mut m = vec![Felt::zero(); n * n];

    // num_coefs scratch reused per i.
    let mut num_coefs = Vec::with_capacity(n);
    let mut next_coefs = Vec::with_capacity(n + 1);

    for i in 0..n {
        let xi = Felt::from_canonical_u32(i as u32);

        // Numerator polynomial ∏_{q ≠ i} (x - q), expanded into power form.
        num_coefs.clear();
        num_coefs.push(Felt::one());
        for q in 0..n {
            if q == i {
                continue;
            }
            let xq = Felt::from_canonical_u32(q as u32);
            // new[r+1] += num[r], new[r] -= num[r] * xq
            next_coefs.clear();
            next_coefs.resize(num_coefs.len() + 1, Felt::zero());
            for (r, &c) in num_coefs.iter().enumerate() {
                next_coefs[r + 1] += c;
                next_coefs[r] -= c * xq;
            }
            std::mem::swap(&mut num_coefs, &mut next_coefs);
        }

        // Denominator = ∏_{q ≠ i} (i - q).  Nonzero because the nodes are distinct.
        let mut denom = Felt::one();
        for q in 0..n {
            if q == i {
                continue;
            }
            let xq = Felt::from_canonical_u32(q as u32);
            denom *= xi - xq;
        }
        let denom_inv = denom.inverse();

        for j in 0..n {
            m[j * n + i] = num_coefs[j] * denom_inv;
        }
    }

    m
}

/// Per-K cached Lagrange-to-power matrix for nodes {0, 1, ..., K}.
pub(crate) fn lagrange_matrix(k: usize) -> &'static [Felt] {
    static M_2: OnceLock<Vec<Felt>> = OnceLock::new();
    static M_4: OnceLock<Vec<Felt>> = OnceLock::new();
    static M_8: OnceLock<Vec<Felt>> = OnceLock::new();
    static M_16: OnceLock<Vec<Felt>> = OnceLock::new();
    static M_32: OnceLock<Vec<Felt>> = OnceLock::new();
    static M_64: OnceLock<Vec<Felt>> = OnceLock::new();

    let slot = match k {
        2 => &M_2,
        4 => &M_4,
        8 => &M_8,
        16 => &M_16,
        32 => &M_32,
        64 => &M_64,
        _ => panic!("unsupported product width K={k}"),
    };

    slot.get_or_init(|| build_lagrange_matrix(k)).as_slice()
}

/// Reconstruct a degree-K univariate from the kernel's K block-summed evals using the
/// precomputed Lagrange-to-power matrix.  The kernel evaluates at t = 0, 2, 3, ..., K; the
/// (K+1)st eval p(1) is recovered from the claim.
fn interpolate_from_kernel_evals(
    kernel_evals: &[Ext],
    claim: Ext,
    k: usize,
) -> UnivariatePolynomial<Ext> {
    debug_assert_eq!(kernel_evals.len(), k);
    let n = k + 1;

    // y-values at the K+1 nodes {0, 1, 2, ..., K}.
    let mut y: Vec<Ext> = Vec::with_capacity(n);
    y.push(kernel_evals[0]); // t = 0
    y.push(claim - kernel_evals[0]); // t = 1 (recovered from claim)
    y.extend_from_slice(&kernel_evals[1..]); // t = 2, 3, ..., K

    // Matrix-vector multiply: coef[j] = sum_i M[j * n + i] * y[i].  ext × felt is cheap.
    let m = lagrange_matrix(k);
    let mut coefs: Vec<Ext> = Vec::with_capacity(n);
    for j in 0..n {
        let row_start = j * n;
        let mut acc = Ext::zero();
        for i in 0..n {
            acc += y[i] * m[row_start + i];
        }
        coefs.push(acc);
    }

    UnivariatePolynomial::new(coefs)
}

/// Fused fold-by-alpha + sum-as-poly for the next round.  Reads an input MLE of size
/// `input_height`, writes the folded MLE of size `input_height/2`, and accumulates per-block
/// partial sums for the next round's K eval points.
///
/// Two kernel variants share this launcher:
/// * **Simple** (`thread per x_top`): block size from [`block_size_for_k`], grid covers
///   all x_top values.  Used when K is small enough that register pressure is fine.
/// * **Cooperative** (K threads per x_top, TPB = 256/K): fixed 256-thread block, grid
///   covers x_top values in chunks of TPB.  Used when K is large (≥ 16) to avoid the
///   register cliff in the simple kernel.
fn fused_fix_and_sum<F>(
    mles: &Mle<F, TaskScope>,
    alpha: Ext,
    claim: Ext,
    kernel: unsafe extern "C" fn() -> KernelPtr,
    k: usize,
    coop: bool,
) -> (Mle<Ext, TaskScope>, UnivariatePolynomial<Ext>)
where
    F: Field,
    TaskScope: MleBaseBackend<Ext>,
{
    let input_height = mles.guts().sizes()[1];
    assert!(input_height >= 4, "fused kernel needs at least 4 input entries");
    assert!(input_height.is_power_of_two(), "fused kernel assumes power-of-two heights");
    let output_height = input_height >> 1;
    let num_x_top = output_height >> 1;
    let backend = mles.backend();

    let (block_size, grid_x, shared_mem) = if coop {
        // Cooperative layout: TILES_PER_BLOCK = 256/k tiles per block.
        const COOP_BLOCK_SIZE: usize = 256;
        let tiles_per_block = COOP_BLOCK_SIZE / k;
        let grid_x = num_x_top.div_ceil(tiles_per_block).max(1);
        // Coop kernel uses static __shared__ storage; no dynamic shared mem.
        (COOP_BLOCK_SIZE, grid_x, 0usize)
    } else {
        let block_size = block_size_for_k(k);
        let grid_x = num_x_top.div_ceil(block_size).max(1);
        let num_tiles = block_size.div_ceil(32).max(1);
        let shared_mem = num_tiles * std::mem::size_of::<Ext>();
        (block_size, grid_x, shared_mem)
    };
    let grid_dim: Dim3 = (grid_x, 1, 1).into();

    let mut output: Tensor<Ext, TaskScope> = backend.uninit_mle(k, output_height);
    let mut block_evals = Tensor::<Ext, TaskScope>::with_sizes_in([k, grid_x], backend.clone());

    unsafe {
        let kargs = args!(
            mles.guts().as_ptr(),
            output.as_mut_ptr(),
            alpha,
            block_evals.as_mut_ptr(),
            input_height
        );
        output.assume_init();
        block_evals.assume_init();
        backend.launch_kernel(kernel(), grid_dim, block_size, &kargs, shared_mem).unwrap();
    }

    let block_evals = DeviceTensor::from_raw(block_evals);
    let host_evals = block_evals.sum_dim(1).to_host().unwrap();
    let uni = interpolate_from_kernel_evals(host_evals.as_slice(), claim, k);

    (Mle::new(output), uni)
}

/// Fold all K MLEs along the last variable, using the existing `fix_last_variable` kernel
/// with `width = K`.
pub(crate) fn fold_last_variable<F>(
    mles: &Mle<F, TaskScope>,
    alpha: Ext,
    kernel: unsafe extern "C" fn() -> KernelPtr,
    k: usize,
) -> Mle<Ext, TaskScope>
where
    F: Field,
    TaskScope: MleBaseBackend<Ext>,
{
    let input_height = mles.guts().sizes()[1];
    assert!(input_height > 0);
    let output_height = input_height.div_ceil(2);
    let backend = mles.backend();
    let mut output: Tensor<Ext, TaskScope> = backend.uninit_mle(k, output_height);

    const BLOCK_SIZE: usize = 256;
    let grid_x = output_height.div_ceil(BLOCK_SIZE);
    let grid_dim: Dim3 = (grid_x, k, 1).into();

    let kargs = args!(mles.guts().as_ptr(), output.as_mut_ptr(), alpha, input_height, k);

    unsafe {
        output.assume_init();
        backend.launch_kernel(kernel(), grid_dim, BLOCK_SIZE, &kargs, 0).unwrap();
    }
    Mle::new(output)
}

/// Run a degree-K product sumcheck on K base-field multilinears (stored as one `[K, 2^n]` MLE).
///
/// Round structure:
/// * Round 0 — base-field `sum_as_poly` (no fold yet).
/// * Rounds 1..n-1 — fused `fix_and_sum` (fold by previous alpha + compute this round's
///   univariate in one pass).  Round 1 is base→ext; later rounds are ext→ext.
/// * Final fold — apply the last alpha to extract the K final evaluation claims.
pub fn simple_product_sumcheck<C>(
    k: usize,
    base_mles: Mle<Felt, TaskScope>,
    mut challenger: C,
    initial_claim: Ext,
) -> (PartialSumcheckProof<Ext>, Vec<Ext>)
where
    C: FieldChallenger<Felt>,
{
    assert_eq!(base_mles.num_polynomials(), k, "MLE must be shaped [K, 2^n] with K={k}");
    let num_variables = base_mles.num_variables();
    let n = num_variables as usize;
    assert!(n >= 1, "need at least one variable");

    let mut uni_polys: Vec<UnivariatePolynomial<Ext>> = Vec::with_capacity(n);
    let mut point: Vec<Ext> = Vec::with_capacity(n);

    // Round 0: base-field sum_as_poly (no fold).
    let uni_0 = sum_as_poly(&base_mles, initial_claim, base_sum_as_poly_kernel(k), k);
    observe_uni(&mut challenger, &uni_0);
    uni_polys.push(uni_0);

    let alpha_0: Ext = challenger.sample_ext_element();
    point.insert(0, alpha_0);

    // Final ext MLE; computed below.  We assign it after the last fused step (or, for n==1,
    // by a direct base→ext fold of the round-0 alpha).
    let final_mle: Mle<Ext, TaskScope> = if n == 1 {
        // Only one round; just fold by alpha_0 to recover the K final evals.
        fold_last_variable(
            &base_mles,
            alpha_0,
            mle_fix_last_variable_koala_bear_base_extension_zero_padding,
            k,
        )
    } else {
        let coop = should_use_coop(k);
        let base_kernel =
            if coop { base_fix_and_sum_coop_kernel(k) } else { base_fix_and_sum_kernel(k) };
        let ext_kernel =
            if coop { ext_fix_and_sum_coop_kernel(k) } else { ext_fix_and_sum_kernel(k) };

        // Fused round 1: fold base→ext by alpha_0 AND compute uni_1.
        let claim_1 = uni_polys.last().unwrap().eval_at_point(alpha_0);
        let (mut current, uni_1) =
            fused_fix_and_sum(&base_mles, alpha_0, claim_1, base_kernel, k, coop);
        observe_uni(&mut challenger, &uni_1);
        uni_polys.push(uni_1);

        let alpha_1: Ext = challenger.sample_ext_element();
        point.insert(0, alpha_1);

        // Fused rounds 2..n-1: fold by the previous alpha, compute the new univariate.
        for _ in 2..n {
            let alpha_prev = *point.first().unwrap();
            let claim_r = uni_polys.last().unwrap().eval_at_point(alpha_prev);
            let (new_mle, uni_r) =
                fused_fix_and_sum(&current, alpha_prev, claim_r, ext_kernel, k, coop);
            observe_uni(&mut challenger, &uni_r);
            uni_polys.push(uni_r);

            let alpha_r: Ext = challenger.sample_ext_element();
            point.insert(0, alpha_r);
            current = new_mle;
        }

        // Final fold by alpha_{n-1}.
        let alpha_last = *point.first().unwrap();
        fold_last_variable(
            &current,
            alpha_last,
            mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
            k,
        )
    };

    // The folded MLE is now [K, 1] — pull the K final evaluation claims back to the host.
    let final_evals_tensor = DeviceTensor::copy_to_host(final_mle.guts()).unwrap();
    let final_evals: Vec<Ext> = final_evals_tensor.as_slice().to_vec();

    let final_claim = uni_polys.last().unwrap().eval_at_point(*point.first().unwrap());
    let proof = PartialSumcheckProof {
        univariate_polys: uni_polys.clone(),
        claimed_sum: initial_claim,
        point_and_eval: (point.clone().into(), final_claim),
    };
    (proof, final_evals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{distributions::Standard, rngs::StdRng, Rng, SeedableRng};
    use slop_alloc::{Buffer, CpuBackend};
    use slop_challenger::IopCtx;
    use slop_sumcheck::partially_verify_sumcheck_proof;
    use slop_tensor::Dimensions;
    use sp1_gpu_cudart::{run_sync_in_place, DeviceBuffer};
    use sp1_gpu_utils::config::TestGC;

    /// `n` here is the number of variables of each individual base MLE.  Small enough to keep
    /// tests cheap, but ≥ 2 so the last fused round (input_height = 4 ⇒ numXTop = 1) actually
    /// runs — that's the regime that exercised the coop kernel's deadlock fix.
    const TEST_N_VARS: u32 = 12;

    /// Runs the full sumcheck for the claim `sum_{x ∈ {0,1}^n} ∏_j A_j(x)` and verifies it three
    /// ways:
    /// * the transcript-level `partially_verify_sumcheck_proof` accepts the proof,
    /// * the product of the K returned final-evaluation claims equals the proof's evaluation
    ///   claim,
    /// * each per-MLE final-evaluation claim equals the host evaluation of A_j at the sumcheck
    ///   point.
    fn run_test_for_k(k: usize, seed: u64) {
        let mle_height = 1usize << TEST_N_VARS;
        let total_len = k * mle_height;

        let mut rng = StdRng::seed_from_u64(seed);
        let host_data: Vec<Felt> = (&mut rng).sample_iter(Standard).take(total_len).collect();

        // Initial claim = sum over the hypercube of the product of all K MLE values.
        let mut initial_claim_felt = Felt::zero();
        for i in 0..mle_height {
            let mut prod = Felt::one();
            for j in 0..k {
                prod *= host_data[j * mle_height + i];
            }
            initial_claim_felt += prod;
        }
        let initial_claim = Ext::from_base(initial_claim_felt);

        // Run the GPU sumcheck.
        let host_buf: Buffer<Felt, CpuBackend> = host_data.clone().into();
        let (proof, final_evals) = run_sync_in_place(|scope| {
            let storage = DeviceBuffer::from_host(&host_buf, &scope).unwrap().into_inner();
            let dimensions = Dimensions::try_from([k, mle_height]).unwrap();
            let mles = Mle::new(Tensor { storage, dimensions });
            let mut challenger = TestGC::default_challenger();
            simple_product_sumcheck(k, mles, &mut challenger, initial_claim)
        })
        .unwrap();

        // Transcript-level verification.
        let mut verifier_challenger = TestGC::default_challenger();
        partially_verify_sumcheck_proof(&proof, &mut verifier_challenger, TEST_N_VARS as usize, k)
            .expect("sumcheck verification failed");

        // The evaluation claim should be ∏_j final_evals[j].
        let mut prod_final = Ext::one();
        for v in &final_evals {
            prod_final *= *v;
        }
        assert_eq!(
            prod_final, proof.point_and_eval.1,
            "K={k}: product of final evaluations does not match evaluation claim"
        );

        // Each per-MLE final claim should match a fresh host evaluation of A_j at the sumcheck
        // point.  Slop's CpuBackend Mle stores guts as `[num_entries, num_polynomials]`; we have
        // one polynomial of `mle_height` entries per MLE here.
        let point = proof.point_and_eval.0.clone();
        for j in 0..k {
            let slice = &host_data[j * mle_height..(j + 1) * mle_height];
            let buf: Buffer<Felt, CpuBackend> = slice.to_vec().into();
            let tensor = Tensor::from(buf).reshape([mle_height, 1]);
            let mle_j: Mle<Felt, CpuBackend> = Mle::new(tensor);
            let host_eval = mle_j.blocking_eval_at::<Ext>(&point);
            assert_eq!(
                host_eval[0], final_evals[j],
                "K={k}, j={j}: host MLE eval at sumcheck point does not match GPU final eval"
            );
        }
    }

    #[test]
    fn test_product_sumcheck_k2() {
        run_test_for_k(2, 0xa1b2_c3d4);
    }

    #[test]
    fn test_product_sumcheck_k4() {
        run_test_for_k(4, 0xa1b2_c3d4);
    }

    #[test]
    fn test_product_sumcheck_k8() {
        run_test_for_k(8, 0xa1b2_c3d4);
    }

    #[test]
    fn test_product_sumcheck_k16() {
        run_test_for_k(16, 0xa1b2_c3d4);
    }

    #[test]
    fn test_product_sumcheck_k32() {
        run_test_for_k(32, 0xa1b2_c3d4);
    }

    #[test]
    fn test_product_sumcheck_k64() {
        run_test_for_k(64, 0xa1b2_c3d4);
    }
}
