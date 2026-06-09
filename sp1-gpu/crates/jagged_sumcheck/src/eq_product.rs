//! GPU prover for an eq-prefixed degree-(K+1) product sumcheck (K=64) — the two-stage-GKR
//! Option 1 shape.  See `slop/crates/jagged/src/eq_product.rs` for the algorithmic write-up.
//!
//! Round structure mirrors the plain product prover:
//! * Round 0 — `eqProductSumAsPolyCoop` (no fold).
//! * Rounds 1..n-1 — `eqProductFixAndSumAsPolyCoop`: in one pass, fold the K-batched MLE by
//!   the previous alpha, fold the eq prefix by `eq(ζ_prev, α_prev)`, and compute this
//!   round's sum-as-poly on the folded data.  This avoids reloading the K-MLE and eq
//!   prefix between rounds.
//! * Final fold — fold the K-batched MLE by α_{n-1} to extract the K final eval claims.
//!
//! The initial eq prefix `E_1` is built directly on the device via the existing GPU
//! `partial_lagrange` kernel.
//!
//! For each round, the host recovers h_r(1) from the round claim via the Gruen identity,
//! applies the cached (K+1)² Lagrange-to-power matrix to get h_r in power form, and
//! multiplies by `(1 − ζ_r) + (2 ζ_r − 1) · t` to produce g_r (degree K+1).

use slop_algebra::{AbstractField, Field, UnivariatePolynomial};
use slop_alloc::{Buffer, CpuBackend};
use slop_challenger::FieldChallenger;
use slop_multilinear::{Mle, Point};
use slop_sumcheck::PartialSumcheckProof;
use slop_tensor::{Dimensions, Tensor};
use sp1_gpu_cudart::sys::kernels::{
    eq_product_fix_and_sum_base_64_coop_kernel, eq_product_fix_and_sum_ext_64_coop_kernel,
    eq_product_sum_as_poly_base_64_coop_kernel,
    mle_fix_last_variable_koala_bear_base_extension_zero_padding,
    mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
};
use sp1_gpu_cudart::sys::runtime::{Dim3, KernelPtr};
use sp1_gpu_cudart::{args, DeviceBuffer, DevicePoint, DeviceTensor, TaskScope};
use sp1_gpu_utils::{Ext, Felt};

use crate::product::{fold_last_variable, lagrange_matrix, observe_uni};

/// Number of factors.  This shim is K=64-only.
const K: usize = 64;
const COOP_BLOCK_SIZE: usize = 256;
const TILES_PER_BLOCK: usize = COOP_BLOCK_SIZE / K; // 4

/// Run the eq-prefixed degree-(K+1) product sumcheck for K=64 base-field MLEs.
///
/// `zeta` has one ext per MLE variable; `z` has one ext per factor.  Round messages are
/// degree-(K+1) (verifier expects expected_degree = K+1).
pub fn simple_eq_product_sumcheck<C>(
    base_mles: Mle<Felt, TaskScope>,
    zeta: Vec<Ext>,
    z: Vec<Ext>,
    mut challenger: C,
    initial_claim: Ext,
) -> (PartialSumcheckProof<Ext>, Vec<Ext>)
where
    C: FieldChallenger<Felt>,
{
    assert_eq!(base_mles.num_polynomials(), K, "this shim is K=64 only");
    let num_variables = base_mles.num_variables();
    let n = num_variables as usize;
    assert_eq!(zeta.len(), n, "zeta must have one ext element per MLE variable");
    assert_eq!(z.len(), K, "z must have K=64 ext elements");
    assert!(n >= 1, "need at least one variable");

    let scope = base_mles.backend().clone();

    // a_j = 1 − z_j; b_j = 2 z_j − 1.  Computed on host, uploaded once.
    let a_host: Vec<Ext> = z.iter().map(|zj| Ext::one() - *zj).collect();
    let b_host: Vec<Ext> = z.iter().map(|zj| *zj + *zj - Ext::one()).collect();
    let a_dev = upload_ext_vec(&a_host, &scope);
    let b_dev = upload_ext_vec(&b_host, &scope);

    // Initial eq prefix E_1 built on device via partial_lagrange of ζ[..n−1].
    let mut current_eq = build_initial_eq_prefix_on_device(&zeta, &scope);

    let mut zetas = zeta;
    let mut uni_polys: Vec<UnivariatePolynomial<Ext>> = Vec::with_capacity(n);
    let mut point: Vec<Ext> = Vec::with_capacity(n);

    // Round 0: base-field sum_as_poly (no fold).
    let zeta_r_0 = *zetas.last().unwrap();
    let uni_0 = compute_round_univariate_eq_no_fold(
        &base_mles,
        &current_eq,
        &a_dev,
        &b_dev,
        zeta_r_0,
        initial_claim,
        eq_product_sum_as_poly_base_64_coop_kernel,
    );
    observe_uni(&mut challenger, &uni_0);
    uni_polys.push(uni_0);

    let alpha_0: Ext = challenger.sample_ext_element();
    point.insert(0, alpha_0);

    let final_mle: Mle<Ext, TaskScope> = if n == 1 {
        // Only round — fold base→ext to recover K final eval claims.
        fold_last_variable(
            &base_mles,
            alpha_0,
            mle_fix_last_variable_koala_bear_base_extension_zero_padding,
            K,
        )
    } else {
        // FUSED round 1 (base→ext): fold MLE by α_0, fold eq prefix by
        // eq(ζ_r_0, α_0), compute h_1.
        let scalar = eq_scalar(zeta_r_0, alpha_0);
        zetas.pop();

        let zeta_r_1 = *zetas.last().unwrap();
        let claim_1 = uni_polys.last().unwrap().eval_at_point(alpha_0);
        let (mut current_mle, mut next_eq, uni_1) = fused_fix_and_sum_eq(
            &base_mles,
            &current_eq,
            &a_dev,
            &b_dev,
            alpha_0,
            scalar,
            zeta_r_1,
            claim_1,
            eq_product_fix_and_sum_base_64_coop_kernel,
        );
        current_eq = next_eq;
        observe_uni(&mut challenger, &uni_1);
        uni_polys.push(uni_1);

        let alpha_1: Ext = challenger.sample_ext_element();
        point.insert(0, alpha_1);

        // FUSED rounds 2..n-1 (ext→ext).
        for _round_idx in 2..n {
            let alpha_prev = *point.first().unwrap();
            let zeta_prev = *zetas.last().unwrap();
            let scalar = eq_scalar(zeta_prev, alpha_prev);
            zetas.pop();

            let zeta_r_current = *zetas.last().unwrap();
            let claim_r = uni_polys.last().unwrap().eval_at_point(alpha_prev);
            let (new_mle, new_eq, uni_r) = fused_fix_and_sum_eq(
                &current_mle,
                &current_eq,
                &a_dev,
                &b_dev,
                alpha_prev,
                scalar,
                zeta_r_current,
                claim_r,
                eq_product_fix_and_sum_ext_64_coop_kernel,
            );
            observe_uni(&mut challenger, &uni_r);
            uni_polys.push(uni_r);

            let alpha_r: Ext = challenger.sample_ext_element();
            point.insert(0, alpha_r);
            current_mle = new_mle;
            next_eq = new_eq;
            current_eq = next_eq;
        }

        // Final fold by α_{n-1} (no eq prefix involved).
        let alpha_last = *point.first().unwrap();
        fold_last_variable(
            &current_mle,
            alpha_last,
            mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
            K,
        )
    };

    // Folded MLE is [K, 1] — pull the K final per-factor evaluation claims to the host.
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

#[inline]
fn eq_scalar(zeta: Ext, alpha: Ext) -> Ext {
    (Ext::one() - zeta) * (Ext::one() - alpha) + zeta * alpha
}

/// Upload a host `Vec<Ext>` as a flat 1×N device tensor.
fn upload_ext_vec(host: &[Ext], scope: &TaskScope) -> Tensor<Ext, TaskScope> {
    let len = host.len();
    let buf_cpu: Buffer<Ext, CpuBackend> = host.to_vec().into();
    let storage = DeviceBuffer::from_host(&buf_cpu, scope).unwrap().into_inner();
    let dimensions = Dimensions::try_from([1, len]).unwrap();
    Tensor { storage, dimensions }
}

/// Build E_1(x) = ∏_{i < n−1} eq(ζ_i, x_i) directly on the device via the existing GPU
/// partial_lagrange kernel.
fn build_initial_eq_prefix_on_device(zeta: &[Ext], scope: &TaskScope) -> Tensor<Ext, TaskScope> {
    let n = zeta.len();
    assert!(n >= 1);
    let zeta_prefix_host: Point<Ext, CpuBackend> = zeta[..n - 1].to_vec().into();
    let device_point = DevicePoint::from_host(&zeta_prefix_host, scope).unwrap();
    device_point.partial_lagrange().into_guts().into_inner()
}

/// Round-0 helper (no fold).
fn compute_round_univariate_eq_no_fold<F>(
    mle: &Mle<F, TaskScope>,
    eq_prefix: &Tensor<Ext, TaskScope>,
    a_dev: &Tensor<Ext, TaskScope>,
    b_dev: &Tensor<Ext, TaskScope>,
    zeta_r: Ext,
    claim: Ext,
    kernel: unsafe extern "C" fn() -> KernelPtr,
) -> UnivariatePolynomial<Ext>
where
    F: Field,
{
    let num_variables = mle.num_variables();
    let scope = mle.backend();

    let num_x_top = 1usize << (num_variables - 1);
    let grid_x = num_x_top.div_ceil(TILES_PER_BLOCK).max(1);
    let grid_dim: Dim3 = (grid_x, 1, 1).into();

    let mut block_evals = Tensor::<Ext, TaskScope>::with_sizes_in([K, grid_x], scope.clone());

    unsafe {
        let kargs = args!(
            block_evals.as_mut_ptr(),
            mle.guts().as_ptr(),
            eq_prefix.as_ptr(),
            a_dev.as_ptr(),
            b_dev.as_ptr(),
            num_x_top
        );
        block_evals.assume_init();
        scope.launch_kernel(kernel(), grid_dim, COOP_BLOCK_SIZE, &kargs, 0).unwrap();
    }

    let block_evals = DeviceTensor::from_raw(block_evals);
    let host_evals = block_evals.sum_dim(1).to_host().unwrap();

    interpolate_from_kernel_evals_eq(host_evals.as_slice(), zeta_r, claim, K)
}

/// Fused fold + eq-prefix update + next-round sum_as_poly in one kernel pass.
///
/// Returns (folded MLE, folded eq prefix, this round's degree-(K+1) univariate g_r(t)).
#[allow(clippy::too_many_arguments)]
fn fused_fix_and_sum_eq<F>(
    mle: &Mle<F, TaskScope>,
    eq_prefix: &Tensor<Ext, TaskScope>,
    a_dev: &Tensor<Ext, TaskScope>,
    b_dev: &Tensor<Ext, TaskScope>,
    alpha: Ext,
    eq_scalar_val: Ext,
    zeta_for_current_round: Ext,
    claim: Ext,
    kernel: unsafe extern "C" fn() -> KernelPtr,
) -> (Mle<Ext, TaskScope>, Tensor<Ext, TaskScope>, UnivariatePolynomial<Ext>)
where
    F: Field,
{
    let input_height = mle.guts().sizes()[1];
    assert!(input_height >= 4, "fused kernel needs at least 4 input entries");
    let output_height = input_height >> 1;
    let num_x_top = output_height >> 1;
    let backend = mle.backend();

    let mut output_mle: Tensor<Ext, TaskScope> =
        Tensor::<Ext, TaskScope>::with_sizes_in([K, output_height], backend.clone());
    let mut output_eq: Tensor<Ext, TaskScope> =
        Tensor::<Ext, TaskScope>::with_sizes_in([1, num_x_top], backend.clone());

    let grid_x = num_x_top.div_ceil(TILES_PER_BLOCK).max(1);
    let grid_dim: Dim3 = (grid_x, 1, 1).into();

    let mut block_evals = Tensor::<Ext, TaskScope>::with_sizes_in([K, grid_x], backend.clone());

    unsafe {
        let kargs = args!(
            mle.guts().as_ptr(),
            output_mle.as_mut_ptr(),
            eq_prefix.as_ptr(),
            output_eq.as_mut_ptr(),
            a_dev.as_ptr(),
            b_dev.as_ptr(),
            alpha,
            eq_scalar_val,
            block_evals.as_mut_ptr(),
            input_height
        );
        output_mle.assume_init();
        output_eq.assume_init();
        block_evals.assume_init();
        backend.launch_kernel(kernel(), grid_dim, COOP_BLOCK_SIZE, &kargs, 0).unwrap();
    }

    let block_evals = DeviceTensor::from_raw(block_evals);
    let host_evals = block_evals.sum_dim(1).to_host().unwrap();
    let uni =
        interpolate_from_kernel_evals_eq(host_evals.as_slice(), zeta_for_current_round, claim, K);

    (Mle::new(output_mle), output_eq, uni)
}

/// Reconstruct g_r(t) (degree K+1) from h_r's K kernel evals at t ∈ {0, 2, …, K}.
fn interpolate_from_kernel_evals_eq(
    kernel_evals: &[Ext],
    zeta_r: Ext,
    claim: Ext,
    k: usize,
) -> UnivariatePolynomial<Ext> {
    let n = k + 1;
    debug_assert_eq!(kernel_evals.len(), k);

    // Recover h_r(1) from the round claim:
    //   g_r(0) + g_r(1) = (1 − ζ_r) h_r(0) + ζ_r h_r(1) = claim
    //   ⇒ h_r(1) = (claim − (1 − ζ_r) h_r(0)) / ζ_r.
    let one_minus_zeta = Ext::one() - zeta_r;
    let h_at_0 = kernel_evals[0];
    let h_at_1 = (claim - one_minus_zeta * h_at_0) * zeta_r.inverse();

    // Assemble y-values at nodes {0, 1, 2, …, K}.
    let mut y: Vec<Ext> = Vec::with_capacity(n);
    y.push(h_at_0);
    y.push(h_at_1);
    y.extend_from_slice(&kernel_evals[1..]);

    // Cached (K+1)² Lagrange-to-power matrix (F-typed, gives cheap ext × felt mults).
    let m = lagrange_matrix(k);
    let mut h_coefs: Vec<Ext> = Vec::with_capacity(n);
    for j in 0..n {
        let row_start = j * n;
        let mut acc = Ext::zero();
        for i in 0..n {
            acc += y[i] * m[row_start + i];
        }
        h_coefs.push(acc);
    }

    // Multiply h_r(t) by eq(ζ_r, t) = (1 − ζ_r) + (2 ζ_r − 1) t.
    let two_zeta_minus_one = zeta_r + zeta_r - Ext::one();
    let mut g_coefs: Vec<Ext> = vec![Ext::zero(); n + 1];
    for j in 0..n {
        g_coefs[j] += one_minus_zeta * h_coefs[j];
        g_coefs[j + 1] += two_zeta_minus_one * h_coefs[j];
    }

    UnivariatePolynomial::new(g_coefs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{distributions::Standard, rngs::StdRng, Rng, SeedableRng};
    use slop_challenger::IopCtx;
    use slop_multilinear::partial_lagrange;
    use slop_sumcheck::partially_verify_sumcheck_proof;
    use sp1_gpu_cudart::run_sync_in_place;
    use sp1_gpu_utils::config::TestGC;

    const TEST_N_VARS: u32 = 5;

    /// Round-trip the GPU eq-prefixed sumcheck for K=64 at n=5 with the TRUE initial claim.
    #[test]
    fn test_eq_product_sumcheck_k64() {
        let mut rng = StdRng::seed_from_u64(0xfaceb00c);

        let mle_height = 1usize << TEST_N_VARS;
        let total_len = K * mle_height;

        let host_data: Vec<Felt> = (&mut rng).sample_iter(Standard).take(total_len).collect();
        let zeta: Vec<Ext> =
            (&mut rng).sample_iter::<Ext, _>(Standard).take(TEST_N_VARS as usize).collect();
        let z: Vec<Ext> = (&mut rng).sample_iter::<Ext, _>(Standard).take(K).collect();

        // True initial claim: ∑_x eq(ζ, x) · ∏_j eq(z_j, p_j(x)).
        let zeta_point: Point<Ext, CpuBackend> = zeta.clone().into();
        let eq_full_tensor = partial_lagrange(&zeta_point);
        let eq_full_slice = eq_full_tensor.as_slice();
        let mut claim = Ext::zero();
        for i in 0..mle_height {
            let mut prod = Ext::one();
            for j in 0..K {
                let p = host_data[j * mle_height + i];
                let factor = (Ext::one() - z[j]) + (z[j] + z[j] - Ext::one()) * p;
                prod *= factor;
            }
            claim += eq_full_slice[i] * prod;
        }

        let host_buf: Buffer<Felt, CpuBackend> = host_data.clone().into();
        let zeta_copy = zeta.clone();
        let z_copy = z.clone();
        let (proof, final_evals) = run_sync_in_place(|scope| {
            let storage = DeviceBuffer::from_host(&host_buf, &scope).unwrap().into_inner();
            let dimensions = Dimensions::try_from([K, mle_height]).unwrap();
            let mles = Mle::new(Tensor { storage, dimensions });
            let mut challenger = TestGC::default_challenger();
            simple_eq_product_sumcheck(mles, zeta_copy, z_copy, &mut challenger, claim)
        })
        .unwrap();

        // (a) Transcript verification.
        let mut verifier_challenger = TestGC::default_challenger();
        partially_verify_sumcheck_proof(
            &proof,
            &mut verifier_challenger,
            TEST_N_VARS as usize,
            K + 1,
        )
        .expect("transcript verification failed");

        let point = proof.point_and_eval.0.clone();

        // (b) Component eval claims == host MLE evals at sumcheck point.
        for j in 0..K {
            let slice = &host_data[j * mle_height..(j + 1) * mle_height];
            let buf: Buffer<Felt, CpuBackend> = slice.to_vec().into();
            let tensor = Tensor::from(buf).reshape([mle_height, 1]);
            let mle_j: Mle<Felt, CpuBackend> = Mle::new(tensor);
            let host_eval = mle_j.blocking_eval_at::<Ext>(&point);
            assert_eq!(
                host_eval[0], final_evals[j],
                "K=64 j={j}: host MLE eval at sumcheck point != claimed final eval"
            );
        }

        // (c) Final eval claim = eq(ζ, point) · ∏_j eq(z_j, p_j(point)).
        let mut eq_at_point = Ext::one();
        for (zi, pi) in zeta.iter().zip(point.iter()) {
            eq_at_point *= (Ext::one() - *zi) * (Ext::one() - *pi) + *zi * *pi;
        }
        let mut factor_prod = Ext::one();
        for (zj, ej) in z.iter().zip(final_evals.iter()) {
            factor_prod *= (Ext::one() - *zj) * (Ext::one() - *ej) + *zj * *ej;
        }
        let expected = eq_at_point * factor_prod;
        assert_eq!(
            expected, proof.point_and_eval.1,
            "K=64: eq(ζ, point) · ∏_j eq(z_j, eval_j) != proof's final eval claim"
        );
    }
}
