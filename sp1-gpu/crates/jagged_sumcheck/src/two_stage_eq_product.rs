//! GPU prover for the two-stage-GKR Option 2 sumcheck.  All five (K_1, K_2) splits of
//! K = 64 are supported via runtime dispatch on the (K_1, K_2) pair: (2, 32), (4, 16),
//! (8, 8), (16, 4), (32, 2).
//!
//! Algorithm overview (see `slop/crates/jagged/src/two_stage_eq_product.rs` for the math):
//!
//!   1. Build K_2 = 8 ext-field outer MLEs `B_j[i] = ∏_{j'} eq(z_{jK_1+j'}, p_{jK_1+j'}[i])`
//!      on device.
//!   2. Run stage 1: eq-prefixed degree-(K_2+1) sumcheck `∑_i eq(ζ, i) · ∏_j B_j[i]`.
//!      Reuses the Option-1 kernel template instantiated with K = K_2 = 8 and (a, b) =
//!      (0, 1), which makes the factor `a + b·B` equal the MLE value itself.
//!   3. Sample ζ''' (log₂ K_2 = 3 ext challenges); compute w = partial_lagrange(ζ''') on
//!      device.  Host pulls w to compute the stage-2 initial claim `∑_j w_j · v_j`.
//!   4. Build stage 2's eq prefix `eq(ζ'', ·)` on device via partial_lagrange.
//!   5. Run stage 2: degree-(K_1+1) sumcheck with the K_2-loop done inside the kernel's
//!      round univariate.  New kernel set (see `two_stage_eq_product_sumcheck.cu`).
//!   6. Final K = K_1·K_2 = 64 evaluation claims `p_k(η)` are pulled from the last folded
//!      stage-2 MLE.
//!
//! For each round, the host recovers h_r(1) from the round claim via the Gruen identity,
//! applies the cached Lagrange-to-power matrix to get h_r in power form, and multiplies by
//! `(1 − ζ_r) + (2 ζ_r − 1) · t` to produce g_r.

use slop_algebra::{AbstractField, Field, UnivariatePolynomial};
use slop_alloc::{Buffer, CpuBackend};
use slop_challenger::FieldChallenger;
use slop_jagged::TwoStageEqProductProof;
use slop_multilinear::{Mle, Point};
use slop_sumcheck::PartialSumcheckProof;
use slop_tensor::{Dimensions, Tensor};
use sp1_gpu_cudart::sys::runtime::{Dim3, KernelPtr};
use sp1_gpu_cudart::sys::v2_kernels::{
    build_b_mles_16_4_kernel, build_b_mles_2_32_kernel, build_b_mles_32_2_kernel,
    build_b_mles_4_16_kernel, build_b_mles_8_8_kernel,
    mle_fix_last_variable_koala_bear_base_extension_zero_padding,
    mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
    two_stage_stage1_fix_and_sum_ext_16_kernel, two_stage_stage1_fix_and_sum_ext_2_kernel,
    two_stage_stage1_fix_and_sum_ext_32_kernel, two_stage_stage1_fix_and_sum_ext_4_kernel,
    two_stage_stage1_fix_and_sum_ext_8_kernel, two_stage_stage1_sum_as_poly_ext_16_kernel,
    two_stage_stage1_sum_as_poly_ext_2_kernel, two_stage_stage1_sum_as_poly_ext_32_kernel,
    two_stage_stage1_sum_as_poly_ext_4_kernel, two_stage_stage1_sum_as_poly_ext_8_kernel,
    two_stage_stage2_fix_and_sum_base_16_4_kernel, two_stage_stage2_fix_and_sum_base_2_32_kernel,
    two_stage_stage2_fix_and_sum_base_32_2_kernel, two_stage_stage2_fix_and_sum_base_4_16_kernel,
    two_stage_stage2_fix_and_sum_base_8_8_kernel, two_stage_stage2_fix_and_sum_ext_16_4_kernel,
    two_stage_stage2_fix_and_sum_ext_2_32_kernel, two_stage_stage2_fix_and_sum_ext_32_2_kernel,
    two_stage_stage2_fix_and_sum_ext_4_16_kernel, two_stage_stage2_fix_and_sum_ext_8_8_kernel,
    two_stage_stage2_sum_as_poly_base_16_4_kernel, two_stage_stage2_sum_as_poly_base_2_32_kernel,
    two_stage_stage2_sum_as_poly_base_32_2_kernel, two_stage_stage2_sum_as_poly_base_4_16_kernel,
    two_stage_stage2_sum_as_poly_base_8_8_kernel,
};
use sp1_gpu_cudart::{args, DeviceBuffer, DevicePoint, DeviceTensor, TaskScope};
use sp1_gpu_utils::{Ext, Felt};

use crate::product::{fold_last_variable, lagrange_matrix, observe_uni};

/// Total factor count K = K_1 · K_2 = 64.
const K: usize = 64;
const COOP_BLOCK_SIZE: usize = 256;

/// Pick the build_b_mles kernel for a given (K_1, K_2) split.
fn build_b_kernel(k1: usize, k2: usize) -> unsafe extern "C" fn() -> KernelPtr {
    match (k1, k2) {
        (2, 32) => build_b_mles_2_32_kernel,
        (4, 16) => build_b_mles_4_16_kernel,
        (8, 8) => build_b_mles_8_8_kernel,
        (16, 4) => build_b_mles_16_4_kernel,
        (32, 2) => build_b_mles_32_2_kernel,
        _ => panic!("unsupported (K_1, K_2) split: ({k1}, {k2})"),
    }
}

/// Stage-1 sum-as-poly kernel for a given K_2.
fn stage1_sum_as_poly_kernel(k2: usize) -> unsafe extern "C" fn() -> KernelPtr {
    match k2 {
        2 => two_stage_stage1_sum_as_poly_ext_2_kernel,
        4 => two_stage_stage1_sum_as_poly_ext_4_kernel,
        8 => two_stage_stage1_sum_as_poly_ext_8_kernel,
        16 => two_stage_stage1_sum_as_poly_ext_16_kernel,
        32 => two_stage_stage1_sum_as_poly_ext_32_kernel,
        _ => panic!("unsupported K_2 = {k2}"),
    }
}

/// Stage-1 fused fix-and-sum kernel for a given K_2 (input is always ext for stage 1).
fn stage1_fix_and_sum_kernel(k2: usize) -> unsafe extern "C" fn() -> KernelPtr {
    match k2 {
        2 => two_stage_stage1_fix_and_sum_ext_2_kernel,
        4 => two_stage_stage1_fix_and_sum_ext_4_kernel,
        8 => two_stage_stage1_fix_and_sum_ext_8_kernel,
        16 => two_stage_stage1_fix_and_sum_ext_16_kernel,
        32 => two_stage_stage1_fix_and_sum_ext_32_kernel,
        _ => panic!("unsupported K_2 = {k2}"),
    }
}

/// Stage-2 base-input sum-as-poly kernel for a given (K_1, K_2) split (round 0).
fn stage2_sum_as_poly_base_kernel(k1: usize, k2: usize) -> unsafe extern "C" fn() -> KernelPtr {
    match (k1, k2) {
        (2, 32) => two_stage_stage2_sum_as_poly_base_2_32_kernel,
        (4, 16) => two_stage_stage2_sum_as_poly_base_4_16_kernel,
        (8, 8) => two_stage_stage2_sum_as_poly_base_8_8_kernel,
        (16, 4) => two_stage_stage2_sum_as_poly_base_16_4_kernel,
        (32, 2) => two_stage_stage2_sum_as_poly_base_32_2_kernel,
        _ => panic!("unsupported (K_1, K_2) split: ({k1}, {k2})"),
    }
}

/// Stage-2 base-input fused kernel for round 1 (base → ext transition).
fn stage2_fix_and_sum_base_kernel(k1: usize, k2: usize) -> unsafe extern "C" fn() -> KernelPtr {
    match (k1, k2) {
        (2, 32) => two_stage_stage2_fix_and_sum_base_2_32_kernel,
        (4, 16) => two_stage_stage2_fix_and_sum_base_4_16_kernel,
        (8, 8) => two_stage_stage2_fix_and_sum_base_8_8_kernel,
        (16, 4) => two_stage_stage2_fix_and_sum_base_16_4_kernel,
        (32, 2) => two_stage_stage2_fix_and_sum_base_32_2_kernel,
        _ => panic!("unsupported (K_1, K_2) split: ({k1}, {k2})"),
    }
}

/// Stage-2 ext-input fused kernel for rounds 2..c-1.
fn stage2_fix_and_sum_ext_kernel(k1: usize, k2: usize) -> unsafe extern "C" fn() -> KernelPtr {
    match (k1, k2) {
        (2, 32) => two_stage_stage2_fix_and_sum_ext_2_32_kernel,
        (4, 16) => two_stage_stage2_fix_and_sum_ext_4_16_kernel,
        (8, 8) => two_stage_stage2_fix_and_sum_ext_8_8_kernel,
        (16, 4) => two_stage_stage2_fix_and_sum_ext_16_4_kernel,
        (32, 2) => two_stage_stage2_fix_and_sum_ext_32_2_kernel,
        _ => panic!("unsupported (K_1, K_2) split: ({k1}, {k2})"),
    }
}

/// Output bundle: both stage proofs, the K_2 mid-protocol claims, and the K final
/// evaluations.  Re-exported from `slop-jagged` so prover and verifier share one shape.
pub type TwoStageProof = TwoStageEqProductProof<Ext>;

/// Run the two-stage-GKR Option 2 sumcheck for a chosen `(k1, k2)` split with k1·k2 = 64.
///
/// Inputs: `base_mles` is K-batched (K rows = factor index, height = 2^c).  ζ ∈ EF^c,
/// z ∈ EF^K.  `initial_claim` is the original `∑_i eq(ζ, i) · ∏_k eq(z_k, p_k[i])` value.
pub fn simple_two_stage_eq_product_sumcheck<C>(
    base_mles: Mle<Felt, TaskScope>,
    zeta: Vec<Ext>,
    z: Vec<Ext>,
    k1: usize,
    k2: usize,
    challenger: &mut C,
    initial_claim: Ext,
) -> TwoStageProof
where
    C: FieldChallenger<Felt>,
{
    assert_eq!(k1 * k2, K, "K_1·K_2 must equal {K}");
    assert_eq!(base_mles.num_polynomials(), K, "MLE must have K = 64 columns");
    let num_variables = base_mles.num_variables();
    let n = num_variables as usize;
    assert_eq!(zeta.len(), n, "zeta must have one ext element per MLE variable");
    assert_eq!(z.len(), K, "z must have K = 64 ext elements");
    assert!(n >= 1, "need at least one variable");

    let scope = base_mles.backend().clone();
    let height = 1usize << num_variables;

    // (a_kk, b_kk) = (1 − z_kk, 2 z_kk − 1) — same across both stages.  Uploaded once.
    let a_host: Vec<Ext> = z.iter().map(|zk| Ext::one() - *zk).collect();
    let b_host: Vec<Ext> = z.iter().map(|zk| *zk + *zk - Ext::one()).collect();
    let a_dev = upload_ext_vec(&a_host, &scope);
    let b_dev = upload_ext_vec(&b_host, &scope);

    // Stage 1 inner factors are the K_2 B_j values; with z_stage1 = 1, (a_stage1, b_stage1)
    // = (0, 1) so the K-templated eq-product kernel reduces to `factor = B_j[i]`.
    let zero_k2_host: Vec<Ext> = vec![Ext::zero(); k2];
    let one_k2_host: Vec<Ext> = vec![Ext::one(); k2];
    let a_stage1 = upload_ext_vec(&zero_k2_host, &scope);
    let b_stage1 = upload_ext_vec(&one_k2_host, &scope);

    // -------- Build B_j on device. --------
    let b_mles = build_b_mles_on_device(&base_mles, &a_dev, &b_dev, height, k1, k2, &scope);

    // -------- Stage 1: degree-(k2+1) eq-product on the B_j MLE. --------
    let stage1_eq_prefix = build_initial_eq_prefix_on_device(&zeta, &scope);

    // Sample `_lambda1` to mirror the CPU prover and verifier — they both
    // consume one ext element of FS here (used by `reduce_sumcheck_to_evaluation`
    // as the batching scalar; with a single-poly stage1 the value is unused but
    // the FS draw must still happen).
    let _lambda1: Ext = challenger.sample_ext_element();

    let stage1_sum_kernel = stage1_sum_as_poly_kernel(k2);
    let stage1_fix_kernel = stage1_fix_and_sum_kernel(k2);
    let (stage1_proof, stage1_evals) = run_kx_eq_product_sumcheck::<Ext>(
        b_mles,
        stage1_eq_prefix,
        &a_stage1,
        &b_stage1,
        zeta.clone(),
        challenger,
        initial_claim,
        k2,
        stage1_sum_kernel,
        // Stage 1 input is already ext, so round-1's transition is ext→ext using the
        // SAME fused kernel (no separate base→ext kernel needed).
        stage1_fix_kernel,
        stage1_fix_kernel,
        mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
    );
    assert_eq!(stage1_evals.len(), k2);
    let v: Vec<Ext> = stage1_evals.clone();
    challenger.observe_ext_element_slice(&v);
    let zeta_pp: Vec<Ext> = stage1_proof.point_and_eval.0.iter().copied().collect();

    // -------- ζ''' challenge → w (k2 ext values). --------
    let log_k2 = k2.trailing_zeros() as usize;
    let zeta_ppp: Vec<Ext> = (0..log_k2).map(|_| challenger.sample_ext_element()).collect();
    let w_tensor: DeviceTensor<Ext> = {
        let point: Point<Ext, CpuBackend> = zeta_ppp.into();
        let dpoint = DevicePoint::from_host(&point, &scope).unwrap();
        DeviceTensor::from_raw(dpoint.partial_lagrange().into_guts().into_inner())
    };
    let w_host = w_tensor.to_host().unwrap().as_slice().to_vec();
    let w_dev = w_tensor.into_inner();

    let stage2_claim: Ext =
        w_host.iter().zip(v.iter()).fold(Ext::zero(), |acc, (wj, vj)| acc + *wj * *vj);

    // -------- Stage 2: degree-(k1+1) sumcheck with k2 outer sum. --------
    let stage2_eq_prefix = build_initial_eq_prefix_on_device(&zeta_pp, &scope);

    // Sample `_lambda2` to mirror the CPU prover and verifier — same rationale
    // as `_lambda1` above.
    let _lambda2: Ext = challenger.sample_ext_element();

    let (stage2_proof, final_evals) = run_stage2_sumcheck(
        base_mles,
        stage2_eq_prefix,
        &a_dev,
        &b_dev,
        &w_dev,
        zeta_pp,
        k1,
        k2,
        challenger,
        stage2_claim,
    );
    challenger.observe_ext_element_slice(&final_evals);

    TwoStageProof { stage1: stage1_proof, v, stage2: stage2_proof, final_evals }
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

/// Build E_1(x) over ζ[..n−1] via the existing GPU partial_lagrange kernel.
fn build_initial_eq_prefix_on_device(zeta: &[Ext], scope: &TaskScope) -> Tensor<Ext, TaskScope> {
    let n = zeta.len();
    assert!(n >= 1);
    let zeta_prefix_host: Point<Ext, CpuBackend> = zeta[..n - 1].to_vec().into();
    let device_point = DevicePoint::from_host(&zeta_prefix_host, scope).unwrap();
    device_point.partial_lagrange().into_guts().into_inner()
}

/// Build B_j on device: one ext value per (j, i) pair, K_2 cols × height.
fn build_b_mles_on_device(
    base_mles: &Mle<Felt, TaskScope>,
    a_dev: &Tensor<Ext, TaskScope>,
    b_dev: &Tensor<Ext, TaskScope>,
    height: usize,
    k1: usize,
    k2: usize,
    scope: &TaskScope,
) -> Mle<Ext, TaskScope> {
    let total = height * k2;
    const TPB: usize = 256;
    let grid_x = total.div_ceil(TPB).max(1);
    let grid_dim: Dim3 = (grid_x, 1, 1).into();

    let mut b_tensor: Tensor<Ext, TaskScope> =
        Tensor::<Ext, TaskScope>::with_sizes_in([k2, height], scope.clone());

    unsafe {
        let kargs = args!(
            b_tensor.as_mut_ptr(),
            base_mles.guts().as_ptr(),
            a_dev.as_ptr(),
            b_dev.as_ptr(),
            height
        );
        b_tensor.assume_init();
        scope.launch_kernel(build_b_kernel(k1, k2)(), grid_dim, TPB, &kargs, 0).unwrap();
    }

    Mle::new(b_tensor)
}

/// Generic eq-prefixed degree-(K+1) sumcheck for any K instantiated in the kernel zoo.
/// `kernel_base_to_ext` is the round-1 fused kernel that consumes a base-field MLE; for
/// stage 1 we just pass the ext→ext kernel since the input is already ext.
#[allow(clippy::too_many_arguments)]
fn run_kx_eq_product_sumcheck<F>(
    initial_mles: Mle<F, TaskScope>,
    mut current_eq: Tensor<Ext, TaskScope>,
    a_dev: &Tensor<Ext, TaskScope>,
    b_dev: &Tensor<Ext, TaskScope>,
    zeta: Vec<Ext>,
    challenger: &mut impl FieldChallenger<Felt>,
    initial_claim: Ext,
    k: usize,
    sum_as_poly_kernel: unsafe extern "C" fn() -> KernelPtr,
    fix_and_sum_base_kernel: unsafe extern "C" fn() -> KernelPtr,
    fix_and_sum_ext_kernel: unsafe extern "C" fn() -> KernelPtr,
    final_fold_kernel: unsafe extern "C" fn() -> KernelPtr,
) -> (PartialSumcheckProof<Ext>, Vec<Ext>)
where
    F: Field,
{
    let num_variables = initial_mles.num_variables();
    let n = num_variables as usize;
    let mut zetas = zeta;
    let mut uni_polys: Vec<UnivariatePolynomial<Ext>> = Vec::with_capacity(n);
    let mut point: Vec<Ext> = Vec::with_capacity(n);

    // Round 0.
    let zeta_r_0 = *zetas.last().unwrap();
    let uni_0 = compute_round_univariate_eq_no_fold(
        &initial_mles,
        &current_eq,
        a_dev,
        b_dev,
        zeta_r_0,
        initial_claim,
        sum_as_poly_kernel,
        k,
    );
    observe_uni(challenger, &uni_0);
    uni_polys.push(uni_0);

    let alpha_0: Ext = challenger.sample_ext_element();
    point.insert(0, alpha_0);

    // Final-fold-only path for n = 1.
    let final_mle: Mle<Ext, TaskScope> = if n == 1 {
        fold_last_variable(&initial_mles, alpha_0, final_fold_kernel, k)
    } else {
        // FUSED round 1.
        let scalar = eq_scalar(zeta_r_0, alpha_0);
        zetas.pop();
        let zeta_r_1 = *zetas.last().unwrap();
        let claim_1 = uni_polys.last().unwrap().eval_at_point(alpha_0);
        let (mut current_mle, next_eq, uni_1) = fused_fix_and_sum_eq(
            &initial_mles,
            &current_eq,
            a_dev,
            b_dev,
            alpha_0,
            scalar,
            zeta_r_1,
            claim_1,
            fix_and_sum_base_kernel,
            k,
        );
        current_eq = next_eq;
        observe_uni(challenger, &uni_1);
        uni_polys.push(uni_1);
        let alpha_1: Ext = challenger.sample_ext_element();
        point.insert(0, alpha_1);

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
                a_dev,
                b_dev,
                alpha_prev,
                scalar,
                zeta_r_current,
                claim_r,
                fix_and_sum_ext_kernel,
                k,
            );
            observe_uni(challenger, &uni_r);
            uni_polys.push(uni_r);
            let alpha_r: Ext = challenger.sample_ext_element();
            point.insert(0, alpha_r);
            current_mle = new_mle;
            current_eq = new_eq;
        }

        let alpha_last = *point.first().unwrap();
        fold_last_variable(
            &current_mle,
            alpha_last,
            mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
            k,
        )
    };

    let final_evals_tensor = DeviceTensor::copy_to_host(final_mle.guts()).unwrap();
    let final_evals: Vec<Ext> = final_evals_tensor.as_slice().to_vec();

    let final_claim = uni_polys.last().unwrap().eval_at_point(*point.first().unwrap());
    let proof = PartialSumcheckProof {
        univariate_polys: uni_polys,
        claimed_sum: initial_claim,
        point_and_eval: (point.into(), final_claim),
    };
    (proof, final_evals)
}

/// Round-0 helper for the K-templated eq-product kernel.
#[allow(clippy::too_many_arguments)]
fn compute_round_univariate_eq_no_fold<F>(
    mle: &Mle<F, TaskScope>,
    eq_prefix: &Tensor<Ext, TaskScope>,
    a_dev: &Tensor<Ext, TaskScope>,
    b_dev: &Tensor<Ext, TaskScope>,
    zeta_r: Ext,
    claim: Ext,
    kernel: unsafe extern "C" fn() -> KernelPtr,
    k: usize,
) -> UnivariatePolynomial<Ext>
where
    F: Field,
{
    let num_variables = mle.num_variables();
    let scope = mle.backend();
    let tiles_per_block = COOP_BLOCK_SIZE / k;

    let num_x_top = 1usize << (num_variables - 1);
    let grid_x = num_x_top.div_ceil(tiles_per_block).max(1);
    let grid_dim: Dim3 = (grid_x, 1, 1).into();

    let mut block_evals = Tensor::<Ext, TaskScope>::with_sizes_in([k, grid_x], scope.clone());

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
    interpolate_from_kernel_evals_eq(host_evals.as_slice(), zeta_r, claim, k)
}

/// Fused fix + eq-prefix transition + next-round sum_as_poly for the K-templated kernel.
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
    k: usize,
) -> (Mle<Ext, TaskScope>, Tensor<Ext, TaskScope>, UnivariatePolynomial<Ext>)
where
    F: Field,
{
    let input_height = mle.guts().sizes()[1];
    assert!(input_height >= 4, "fused kernel needs at least 4 input entries");
    let output_height = input_height >> 1;
    let num_x_top = output_height >> 1;
    let backend = mle.backend();
    let tiles_per_block = COOP_BLOCK_SIZE / k;

    let mut output_mle: Tensor<Ext, TaskScope> =
        Tensor::<Ext, TaskScope>::with_sizes_in([k, output_height], backend.clone());
    let mut output_eq: Tensor<Ext, TaskScope> =
        Tensor::<Ext, TaskScope>::with_sizes_in([1, num_x_top], backend.clone());

    let grid_x = num_x_top.div_ceil(tiles_per_block).max(1);
    let grid_dim: Dim3 = (grid_x, 1, 1).into();

    let mut block_evals = Tensor::<Ext, TaskScope>::with_sizes_in([k, grid_x], backend.clone());

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
        interpolate_from_kernel_evals_eq(host_evals.as_slice(), zeta_for_current_round, claim, k);

    (Mle::new(output_mle), output_eq, uni)
}

// -------------------- Stage 2 driver --------------------

#[allow(clippy::too_many_arguments)]
fn run_stage2_sumcheck(
    base_mles: Mle<Felt, TaskScope>,
    mut current_eq: Tensor<Ext, TaskScope>,
    a_dev: &Tensor<Ext, TaskScope>,
    b_dev: &Tensor<Ext, TaskScope>,
    w_dev: &Tensor<Ext, TaskScope>,
    zeta: Vec<Ext>,
    k1: usize,
    k2: usize,
    challenger: &mut impl FieldChallenger<Felt>,
    initial_claim: Ext,
) -> (PartialSumcheckProof<Ext>, Vec<Ext>) {
    let num_variables = base_mles.num_variables();
    let n = num_variables as usize;
    let mut zetas = zeta;
    let mut uni_polys: Vec<UnivariatePolynomial<Ext>> = Vec::with_capacity(n);
    let mut point: Vec<Ext> = Vec::with_capacity(n);

    let sum_as_poly_base = stage2_sum_as_poly_base_kernel(k1, k2);
    let fix_and_sum_base = stage2_fix_and_sum_base_kernel(k1, k2);
    let fix_and_sum_ext = stage2_fix_and_sum_ext_kernel(k1, k2);

    // Round 0 (base-field sum_as_poly).
    let zeta_r_0 = *zetas.last().unwrap();
    let uni_0 = stage2_compute_round_univariate_no_fold(
        &base_mles,
        &current_eq,
        a_dev,
        b_dev,
        w_dev,
        zeta_r_0,
        initial_claim,
        k1,
        sum_as_poly_base,
    );
    observe_uni(challenger, &uni_0);
    uni_polys.push(uni_0);

    let alpha_0: Ext = challenger.sample_ext_element();
    point.insert(0, alpha_0);

    let final_mle: Mle<Ext, TaskScope> = if n == 1 {
        fold_last_variable(
            &base_mles,
            alpha_0,
            mle_fix_last_variable_koala_bear_base_extension_zero_padding,
            K,
        )
    } else {
        // FUSED round 1 (base→ext).
        let scalar = eq_scalar(zeta_r_0, alpha_0);
        zetas.pop();
        let zeta_r_1 = *zetas.last().unwrap();
        let claim_1 = uni_polys.last().unwrap().eval_at_point(alpha_0);
        let (mut current_mle, next_eq, uni_1) = stage2_fused_fix_and_sum(
            &base_mles,
            &current_eq,
            a_dev,
            b_dev,
            w_dev,
            alpha_0,
            scalar,
            zeta_r_1,
            claim_1,
            k1,
            fix_and_sum_base,
        );
        current_eq = next_eq;
        observe_uni(challenger, &uni_1);
        uni_polys.push(uni_1);
        let alpha_1: Ext = challenger.sample_ext_element();
        point.insert(0, alpha_1);

        for _round_idx in 2..n {
            let alpha_prev = *point.first().unwrap();
            let zeta_prev = *zetas.last().unwrap();
            let scalar = eq_scalar(zeta_prev, alpha_prev);
            zetas.pop();
            let zeta_r_current = *zetas.last().unwrap();
            let claim_r = uni_polys.last().unwrap().eval_at_point(alpha_prev);
            let (new_mle, new_eq, uni_r) = stage2_fused_fix_and_sum(
                &current_mle,
                &current_eq,
                a_dev,
                b_dev,
                w_dev,
                alpha_prev,
                scalar,
                zeta_r_current,
                claim_r,
                k1,
                fix_and_sum_ext,
            );
            observe_uni(challenger, &uni_r);
            uni_polys.push(uni_r);
            let alpha_r: Ext = challenger.sample_ext_element();
            point.insert(0, alpha_r);
            current_mle = new_mle;
            current_eq = new_eq;
        }

        let alpha_last = *point.first().unwrap();
        fold_last_variable(
            &current_mle,
            alpha_last,
            mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
            K,
        )
    };

    let final_evals_tensor = DeviceTensor::copy_to_host(final_mle.guts()).unwrap();
    let final_evals: Vec<Ext> = final_evals_tensor.as_slice().to_vec();

    let final_claim = uni_polys.last().unwrap().eval_at_point(*point.first().unwrap());
    let proof = PartialSumcheckProof {
        univariate_polys: uni_polys,
        claimed_sum: initial_claim,
        point_and_eval: (point.into(), final_claim),
    };
    (proof, final_evals)
}

/// Stage-2 round-0 helper (no fold).  K_1 eval points returned.
#[allow(clippy::too_many_arguments)]
fn stage2_compute_round_univariate_no_fold<F>(
    mle: &Mle<F, TaskScope>,
    eq_prefix: &Tensor<Ext, TaskScope>,
    a_dev: &Tensor<Ext, TaskScope>,
    b_dev: &Tensor<Ext, TaskScope>,
    w_dev: &Tensor<Ext, TaskScope>,
    zeta_r: Ext,
    claim: Ext,
    k1: usize,
    kernel: unsafe extern "C" fn() -> KernelPtr,
) -> UnivariatePolynomial<Ext>
where
    F: Field,
{
    let num_variables = mle.num_variables();
    let scope = mle.backend();
    let tiles_per_block = COOP_BLOCK_SIZE / k1;

    let num_x_top = 1usize << (num_variables - 1);
    let grid_x = num_x_top.div_ceil(tiles_per_block).max(1);
    let grid_dim: Dim3 = (grid_x, 1, 1).into();

    let mut block_evals = Tensor::<Ext, TaskScope>::with_sizes_in([k1, grid_x], scope.clone());

    unsafe {
        let kargs = args!(
            block_evals.as_mut_ptr(),
            mle.guts().as_ptr(),
            eq_prefix.as_ptr(),
            a_dev.as_ptr(),
            b_dev.as_ptr(),
            w_dev.as_ptr(),
            num_x_top
        );
        block_evals.assume_init();
        scope.launch_kernel(kernel(), grid_dim, COOP_BLOCK_SIZE, &kargs, 0).unwrap();
    }

    let block_evals = DeviceTensor::from_raw(block_evals);
    let host_evals = block_evals.sum_dim(1).to_host().unwrap();
    interpolate_from_kernel_evals_eq(host_evals.as_slice(), zeta_r, claim, k1)
}

/// Stage-2 fused fix + eq-prefix transition + next-round sum_as_poly.
#[allow(clippy::too_many_arguments)]
fn stage2_fused_fix_and_sum<F>(
    mle: &Mle<F, TaskScope>,
    eq_prefix: &Tensor<Ext, TaskScope>,
    a_dev: &Tensor<Ext, TaskScope>,
    b_dev: &Tensor<Ext, TaskScope>,
    w_dev: &Tensor<Ext, TaskScope>,
    alpha: Ext,
    eq_scalar_val: Ext,
    zeta_for_current_round: Ext,
    claim: Ext,
    k1: usize,
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
    let tiles_per_block = COOP_BLOCK_SIZE / k1;

    let mut output_mle: Tensor<Ext, TaskScope> =
        Tensor::<Ext, TaskScope>::with_sizes_in([K, output_height], backend.clone());
    let mut output_eq: Tensor<Ext, TaskScope> =
        Tensor::<Ext, TaskScope>::with_sizes_in([1, num_x_top], backend.clone());

    let grid_x = num_x_top.div_ceil(tiles_per_block).max(1);
    let grid_dim: Dim3 = (grid_x, 1, 1).into();

    let mut block_evals = Tensor::<Ext, TaskScope>::with_sizes_in([k1, grid_x], backend.clone());

    unsafe {
        let kargs = args!(
            mle.guts().as_ptr(),
            output_mle.as_mut_ptr(),
            eq_prefix.as_ptr(),
            output_eq.as_mut_ptr(),
            a_dev.as_ptr(),
            b_dev.as_ptr(),
            w_dev.as_ptr(),
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
        interpolate_from_kernel_evals_eq(host_evals.as_slice(), zeta_for_current_round, claim, k1);

    (Mle::new(output_mle), output_eq, uni)
}

/// Reconstruct g_r(t) (degree k+1) from h_r's k kernel evals at t ∈ {0, 2, …, k}.  Mirrors
/// the Option-1 interpolation; the eq-factor structure is identical for both stages.
fn interpolate_from_kernel_evals_eq(
    kernel_evals: &[Ext],
    zeta_r: Ext,
    claim: Ext,
    k: usize,
) -> UnivariatePolynomial<Ext> {
    let n = k + 1;
    debug_assert_eq!(kernel_evals.len(), k);

    let one_minus_zeta = Ext::one() - zeta_r;
    let h_at_0 = kernel_evals[0];
    let h_at_1 = (claim - one_minus_zeta * h_at_0) * zeta_r.inverse();

    let mut y: Vec<Ext> = Vec::with_capacity(n);
    y.push(h_at_0);
    y.push(h_at_1);
    y.extend_from_slice(&kernel_evals[1..]);

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
    use slop_jagged::verify_two_stage_eq_product;
    use slop_multilinear::partial_lagrange;
    use sp1_gpu_cudart::run_sync_in_place;
    use sp1_gpu_utils::config::TestGC;

    const TEST_N_VARS: u32 = 5;

    /// Round-trip the GPU two-stage sumcheck for a given (K_1, K_2) split at n=5.
    fn run_two_stage_test(k1: usize, k2: usize) {
        assert_eq!(k1 * k2, K);
        let mut rng = StdRng::seed_from_u64(0xc0ffee);

        let mle_height = 1usize << TEST_N_VARS;
        let total_len = K * mle_height;
        let host_data: Vec<Felt> = (&mut rng).sample_iter(Standard).take(total_len).collect();
        let zeta: Vec<Ext> =
            (&mut rng).sample_iter::<Ext, _>(Standard).take(TEST_N_VARS as usize).collect();
        let z: Vec<Ext> = (&mut rng).sample_iter::<Ext, _>(Standard).take(K).collect();

        // True initial claim: ∑_i eq(ζ, i) · ∏_k eq(z_k, p_k[i]).
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
        let proof = run_sync_in_place(|scope| {
            let storage = DeviceBuffer::from_host(&host_buf, &scope).unwrap().into_inner();
            let dimensions = Dimensions::try_from([K, mle_height]).unwrap();
            let mles = Mle::new(Tensor { storage, dimensions });
            let mut challenger = TestGC::default_challenger();
            simple_two_stage_eq_product_sumcheck(
                mles,
                zeta_copy,
                z_copy,
                k1,
                k2,
                &mut challenger,
                claim,
            )
        })
        .unwrap();

        // Replay the verifier-side transcript via the shared helper, which checks both
        // stages, the claim transition, the eval-claim consistency, and (via the host-evals
        // closure) that `final_evals[k] == p_k(η)`.
        let mut verifier = TestGC::default_challenger();

        let (stage1_claim, eta, final_evals) = verify_two_stage_eq_product::<Felt, Ext, _>(
            &proof,
            &zeta_point,
            &z,
            k1,
            k2,
            TEST_N_VARS as usize,
            &mut verifier,
        )
        .unwrap_or_else(|e| panic!("({k1},{k2}): two-stage verification failed: {e:?}"));
        assert_eq!(
            stage1_claim, claim,
            "({k1},{k2}): verifier-returned stage1 claim != prover's initial claim",
        );

        let host_storage: Buffer<Felt, CpuBackend> = host_data.into();
        let dimensions = Dimensions::try_from([K, mle_height]).unwrap();
        // The transpose is necessary because the prover copied over the raw buffer to the device
        // which essentially forces the transposed layout on the device.
        let mles = Mle::new(Tensor { storage: host_storage, dimensions }.transpose());

        let expected_final_evals = mles.eval_at(&eta).to_vec();

        for (i, (actual, expected)) in
            final_evals.iter().zip(expected_final_evals.iter()).enumerate()
        {
            assert_eq!(
                actual, expected,
                "({k1},{k2}): final eval {i} does not match expected value"
            );
        }
    }

    #[test]
    fn test_two_stage_eq_product_sumcheck_2_32() {
        run_two_stage_test(2, 32);
    }

    #[test]
    fn test_two_stage_eq_product_sumcheck_4_16() {
        run_two_stage_test(4, 16);
    }

    #[test]
    fn test_two_stage_eq_product_sumcheck_8_8() {
        run_two_stage_test(8, 8);
    }

    #[test]
    fn test_two_stage_eq_product_sumcheck_16_4() {
        run_two_stage_test(16, 4);
    }

    #[test]
    fn test_two_stage_eq_product_sumcheck_32_2() {
        run_two_stage_test(32, 2);
    }
}
