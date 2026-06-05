//! Sync versions of jagged eval sumcheck for GPU (TaskScope).
//! These avoid the async trait overhead since GPU operations are already sync.

use slop_algebra::{interpolate_univariate_polynomial, AbstractField, Field};
use slop_alloc::Buffer;
use slop_challenger::FieldChallenger;
use slop_jagged::{
    sum_z_first_n_via_geq, JaggedLittlePolynomialProverParams, JaggedSumcheckEvalProof,
};
use slop_multilinear::Point;
use slop_sumcheck::PartialSumcheckProof;
use slop_tensor::Tensor;
use sp1_gpu_challenger::FromHostChallengerSync;
use sp1_gpu_cudart::reduce::DeviceSumKernel;
use sp1_gpu_cudart::{
    DeviceBuffer, DevicePoint, DeviceTransposeKernel, PartialLagrangeKernel, TaskScope,
};
use sp1_gpu_utils::{Ext, Felt};

use crate::{AsMutRawChallenger, BranchingProgramKernel, JaggedAssistSumAsPolyGPUImpl};

/// Returns the ceiling of log2 of `n`. If `n` is 0, returns 0.
#[inline]
fn log2_ceil_usize(n: usize) -> usize {
    if n <= 1 {
        0
    } else {
        usize::BITS as usize - (n - 1).leading_zeros() as usize
    }
}

/// GPU-specific sumcheck polynomial state for the jagged eval sumcheck.
/// This is the GPU equivalent of `JaggedEvalSumcheckPoly` in slop-jagged,
/// with all buffers on `TaskScope` (device) instead of `CpuBackend`.
pub struct JaggedEvalSumcheckPolyGPU<DeviceChallenger> {
    pub bp_batch_eval: JaggedAssistSumAsPolyGPUImpl<DeviceChallenger>,
    pub rho: Point<Ext, TaskScope>,
    pub z_col: Point<Ext, TaskScope>,
    pub z_col_eq_vals: Buffer<Ext, TaskScope>,
    pub round_num: usize,
    pub intermediate_eq_full_evals: Buffer<Ext, TaskScope>,
    pub half: Ext,
    pub prefix_sum_dimension: u32,
}

impl<DeviceChallenger> JaggedEvalSumcheckPolyGPU<DeviceChallenger> {
    pub fn num_variables(&self) -> u32 {
        self.prefix_sum_dimension
    }
}

/// Construct a `JaggedEvalSumcheckPolyGPU` from jagged params, with all data on device.
pub fn new_jagged_eval_sumcheck_poly_sync<DeviceChallenger>(
    z_row: Point<Ext>,
    z_col: Point<Ext>,
    z_index: Point<Ext>,
    prefix_sums: Vec<usize>,
    expected_sum: Ext,
    backend: &TaskScope,
) -> JaggedEvalSumcheckPolyGPU<DeviceChallenger>
where
    DeviceChallenger: AsMutRawChallenger + Send + Sync + Clone,
    TaskScope: BranchingProgramKernel<Felt, Ext, DeviceChallenger>
        + DeviceSumKernel<Ext>
        + PartialLagrangeKernel<Ext>
        + DeviceTransposeKernel<Ext>,
{
    let prefix_sum_length = log2_ceil_usize(*prefix_sums.last().unwrap()) + 1;

    // TODO: Avoid the HtoDtoH roundtrip and do the deduplication loop on device.
    let z_col_dev = DevicePoint::from_host(&z_col, backend).unwrap();
    let z_col_partial_lagrange_dev = z_col_dev.partial_lagrange();
    let z_col_partial_lagrange = z_col_partial_lagrange_dev.to_host().unwrap();
    let z_col_lagrange = z_col_partial_lagrange.guts().as_slice();

    // Condense `(curr, next)` prefix-sum pairs by collapsing runs of identical
    // adjacent pairs (= empty-trace columns) and summing their z_col eq values.
    // Each kept pair contributes one column to the BP eval.
    let mut prefix_sum_pairs: Vec<(usize, usize)> = Vec::with_capacity(prefix_sums.len() - 1);
    let mut z_col_eq_vals: Vec<Ext> = Vec::with_capacity(prefix_sums.len() - 1);

    for (window, &eq_val) in prefix_sums.windows(2).zip(z_col_lagrange) {
        let pair = (window[0], window[1]);
        if prefix_sum_pairs.last() == Some(&pair) {
            *z_col_eq_vals.last_mut().unwrap() += eq_val;
        } else {
            prefix_sum_pairs.push(pair);
            z_col_eq_vals.push(eq_val);
        }
    }

    let num_columns = prefix_sum_pairs.len();

    // Sync device copy for z_col
    let z_col_buffer: Buffer<Ext> = z_col.to_vec().into();
    let z_col_device: Point<Ext, TaskScope> =
        Point::new(DeviceBuffer::from_host(&z_col_buffer, backend).unwrap().into_inner());

    let half = Ext::two().inverse();

    let bp_batch_eval = JaggedAssistSumAsPolyGPUImpl::new(
        z_row,
        z_index,
        &prefix_sum_pairs,
        prefix_sum_length,
        expected_sum,
        backend,
    );

    let z_col_eq_vals_buffer = Buffer::<Ext>::from(z_col_eq_vals);
    let z_col_eq_vals_device =
        DeviceBuffer::from_host(&z_col_eq_vals_buffer, backend).unwrap().into_inner();

    let intermediate_eq_full_evals = vec![Ext::one(); num_columns];
    let intermediate_eq_full_evals_buffer = Buffer::<Ext>::from(intermediate_eq_full_evals);
    let intermediate_eq_full_evals_device =
        DeviceBuffer::from_host(&intermediate_eq_full_evals_buffer, backend).unwrap().into_inner();

    JaggedEvalSumcheckPolyGPU {
        bp_batch_eval,
        rho: Point::new(Buffer::with_capacity_in(0, backend.clone())),
        z_col: z_col_device,
        z_col_eq_vals: z_col_eq_vals_device,
        round_num: 0,
        intermediate_eq_full_evals: intermediate_eq_full_evals_device,
        half,
        prefix_sum_dimension: (2 * prefix_sum_length) as u32,
    }
}

/// Sync version of prove_jagged_eval_sumcheck for TaskScope.
/// Uses a single fused cooperative kernel launch for all rounds.
pub fn prove_jagged_eval_sumcheck_sync<DeviceChallenger>(
    mut poly: JaggedEvalSumcheckPolyGPU<DeviceChallenger>,
    challenger: &mut DeviceChallenger,
    claim: Ext,
    _t: usize,
    sum_values: &mut Buffer<Ext, TaskScope>,
    combine_alpha: Ext,
) -> PartialSumcheckProof<Ext>
where
    DeviceChallenger: AsMutRawChallenger + Send + Sync + Clone,
    TaskScope: BranchingProgramKernel<Felt, Ext, DeviceChallenger> + DeviceSumKernel<Ext>,
{
    let num_variables = poly.num_variables() as usize;

    // Single fused cooperative kernel launch for all rounds
    let rho_buffer = poly.bp_batch_eval.fused_sumcheck(
        num_variables,
        &poly.z_col_eq_vals,
        &mut poly.intermediate_eq_full_evals,
        sum_values,
        challenger,
        combine_alpha,
    );

    // Move sum_as_poly evaluations to CPU
    let host_sum_values = unsafe { sum_values.copy_into_host_vec() };

    let univariate_polys = host_sum_values
        .as_slice()
        .chunks_exact(3)
        .map(|chunk| {
            let ys: [Ext; 3] = chunk.try_into().unwrap();
            let xs: [Ext; 3] = [Ext::zero(), Ext::two().inverse(), Ext::one()];
            interpolate_univariate_polynomial(&xs, &ys)
        })
        .collect::<Vec<_>>();

    // Move rho_buffer to CPU and reverse (kernel writes forward, convention is reversed)
    let mut rho_host = unsafe { rho_buffer.copy_into_host_vec() };
    rho_host.reverse();

    let final_claim: Ext =
        univariate_polys.last().unwrap().eval_at_point(rho_host.first().copied().unwrap());

    PartialSumcheckProof {
        univariate_polys,
        claimed_sum: claim,
        point_and_eval: (rho_host.into(), final_claim),
    }
}

/// Sync version of prove_jagged_evaluation for TaskScope.
/// This is the main entry point for sync jagged evaluation proving.
#[allow(clippy::too_many_arguments)]
pub fn prove_jagged_evaluation_sync<HostChallenger, DeviceChallenger>(
    params: &JaggedLittlePolynomialProverParams,
    z_row: &Point<Ext>,
    z_col: &Point<Ext>,
    z_trace: &Point<Ext>,
    challenger: &mut HostChallenger,
    expected_sum: Ext,
    backend: &TaskScope,
) -> JaggedSumcheckEvalProof<Ext>
where
    HostChallenger: FieldChallenger<Felt> + Send + Sync,
    DeviceChallenger:
        AsMutRawChallenger + FromHostChallengerSync<HostChallenger> + Clone + Send + Sync,
    TaskScope: BranchingProgramKernel<Felt, Ext, DeviceChallenger>
        + DeviceSumKernel<Ext>
        + PartialLagrangeKernel<Ext>
        + DeviceTransposeKernel<Ext>,
{
    // Fused (assist + alpha * geq) sumcheck. Mirror the CPU FS order:
    //   1. Sample combine_alpha from the post-outer-sumcheck challenger.
    //   2. Compute the fused claim `expected_sum + alpha * Σ_{real col} z_col_lagrange[col]`.
    //   3. Observe the fused claim, then create the device challenger / run the kernel.
    let combine_alpha: Ext = challenger.sample_ext_element();
    let num_real_pairs = params.col_prefix_sums_usize.len() - 1;
    let sum_z_first_n: Ext = sum_z_first_n_via_geq::<Felt, Ext>(num_real_pairs, z_col);
    let fused_claim = expected_sum + combine_alpha * sum_z_first_n;

    let jagged_eval_sc_poly = new_jagged_eval_sumcheck_poly_sync::<DeviceChallenger>(
        z_row.clone(),
        z_col.clone(),
        z_trace.clone(),
        params.col_prefix_sums_usize.clone(),
        fused_claim,
        backend,
    );

    let log_m = log2_ceil_usize(*params.col_prefix_sums_usize.last().unwrap());

    let mut sum_values = Tensor::zeros_in([3, 2 * (log_m + 1)], backend.clone()).into_buffer();

    challenger.observe_ext_element(fused_claim);

    // Create device challenger sync
    let mut device_challenger = DeviceChallenger::from_host_challenger_sync(challenger, backend);

    // Run sumcheck sync
    let partial_sumcheck_proof = prove_jagged_eval_sumcheck_sync(
        jagged_eval_sc_poly,
        &mut device_challenger,
        fused_claim,
        1,
        &mut sum_values,
        combine_alpha,
    );

    // Sync CPU challenger with device challenger state
    for poly in &partial_sumcheck_proof.univariate_polys {
        // Inline observe_constant_length_extension_slice to avoid VariableLengthChallenger bound
        for &coeff in &poly.coefficients {
            challenger.observe_ext_element(coeff);
        }
        let _: Ext = challenger.sample_ext_element();
    }

    // Recover `real_sum` (the two-stage's initial claim, before the padded
    // contribution) algebraically by inverting the verifier's reconciliation
    // identity:
    //
    //   point_and_eval.1 = real_sum · (assist_bp.eval(curr, next)
    //                                  + α · full_geq(curr, next))
    //
    // so `real_sum = point_and_eval.1 / (assist_eval + α · geq_eval)`.
    //
    // Replaces the previous O(num_cols · K · prefix_sum_length) per-column
    // `full_lagrange_eval` loop (~80 ms at all-chips 2^28) — now a single
    // BP eval + a field division.
    let zeta_sumcheck: Vec<Ext> = partial_sumcheck_proof.point_and_eval.0.iter().copied().collect();
    let (curr_pt, next_pt) =
        slop_jagged::deinterleave_prefix_sums(&partial_sumcheck_proof.point_and_eval.0);
    let assist_bp = slop_jagged::BranchingProgram::<Ext>::new(z_row.clone(), z_trace.clone());
    let assist_eval = assist_bp.eval(&curr_pt, &next_pt);
    let geq_eval = slop_multilinear::full_geq(&curr_pt, &next_pt);
    let denominator = assist_eval + combine_alpha * geq_eval;
    let real_sum = partial_sumcheck_proof.point_and_eval.1 * denominator.inverse();

    let two_stage_proof = run_two_stage_on_gpu(
        &params.col_prefix_sums_usize,
        z_col,
        &zeta_sumcheck,
        real_sum,
        challenger,
        backend,
    );

    JaggedSumcheckEvalProof { partial_sumcheck_proof, two_stage_proof }
}

/// Run the GPU two-stage GKR sumcheck. Builds the K=64 bit MLE on host (cheap
/// — `K · 2^c` writes), uploads to device, calls the GPU
/// `simple_two_stage_eq_product_sumcheck`, and reshapes the resulting proof
/// onto the Ext-typed wire shape.
fn run_two_stage_on_gpu<Chal>(
    prefix_sums: &[usize],
    z_col: &Point<Ext>,
    zeta_sumcheck: &[Ext],
    real_sum: Ext,
    challenger: &mut Chal,
    backend: &TaskScope,
) -> slop_jagged::TwoStageEqProductProof<Ext>
where
    Chal: FieldChallenger<Felt>,
{
    use slop_jagged::{lagrange_eval_at_zero_merged, K1, K2};

    let log_num_cols = z_col.dimension();
    let num_real_pairs = prefix_sums.len() - 1;

    // Padded col contribution: `L(0, ζ) · (1 − sum_z_first_n)`.
    let l_zero = lagrange_eval_at_zero_merged::<Ext>(zeta_sumcheck);
    let sum_z_first_n = sum_z_first_n_via_geq::<Felt, Ext>(num_real_pairs, z_col);
    let padded_contribution = l_zero * (Ext::one() - sum_z_first_n);
    let full_hypercube_sum = real_sum + padded_contribution;

    // Bit-decompose prefix sums directly on device — `[K, two_c]` layout
    // matches what the GPU two-stage sumcheck expects.
    let bit_mle_device =
        crate::bit_decompose::build_bit_mle_on_device(prefix_sums, log_num_cols, backend);

    // Pad ζ_sumcheck to K=64 with zeros at LOW indices (matches padded MSB positions
    // in the bit MLE).
    const K: usize = crate::bit_decompose::K;
    let mut zeta_padded = vec![Ext::zero(); K];
    let offset = K - zeta_sumcheck.len();
    zeta_padded[offset..].copy_from_slice(zeta_sumcheck);

    let z_col_ext: Vec<Ext> = z_col.iter().copied().collect();

    // Run the GPU two-stage sumcheck.  It mutates the host challenger.
    let gpu_proof = sp1_gpu_jagged_sumcheck::simple_two_stage_eq_product_sumcheck(
        bit_mle_device,
        z_col_ext,
        zeta_padded,
        K1,
        K2,
        challenger,
        full_hypercube_sum,
    );

    // Re-wrap on the slop-jagged wire type.  Field types are identical (`Ext`
    // both sides), so this is a regular move — no transmute, no copy.
    slop_jagged::TwoStageEqProductProof {
        stage1: gpu_proof.stage1,
        v: gpu_proof.v,
        stage2: gpu_proof.stage2,
        final_evals: gpu_proof.final_evals,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use slop_alloc::Buffer;
    use slop_challenger::{FieldChallenger, IopCtx};
    use slop_jagged::{
        prove_jagged_eval_sumcheck, JaggedEvalSumcheckPoly, JaggedLittlePolynomialProverParams,
    };
    use slop_multilinear::Point;
    use sp1_gpu_challenger::DuplexChallenger as DeviceDuplexChallenger;
    use sp1_gpu_cudart::TaskScope;
    use sp1_primitives::{SP1GlobalContext, SP1Perm};

    type HostChallenger = slop_challenger::DuplexChallenger<Felt, SP1Perm, 16, 8>;
    type DeviceChallenger = DeviceDuplexChallenger<Felt, TaskScope>;

    /// End-to-end test: run the GPU jagged assist sumcheck prover and compare
    /// its output against the CPU reference implementation.
    #[test]
    fn test_gpu_vs_cpu_jagged_eval_sumcheck() {
        let row_counts = vec![1 << 10, 1 << 8, 0, 1 << 12, 1 << 7, 0, 1 << 11, 1 << 10];
        let log_max_row_count = 12;

        let prover_params =
            JaggedLittlePolynomialProverParams::new(row_counts.clone(), log_max_row_count);

        let mut rng = StdRng::seed_from_u64(42);

        let prefix_sums = &prover_params.col_prefix_sums_usize;
        let log_m = log2_ceil_usize(*prefix_sums.last().unwrap());

        let z_row: Point<Ext> = (0..log_max_row_count).map(|_| rng.gen::<Ext>()).collect();
        let z_col: Point<Ext> =
            (0..log2_ceil_usize(row_counts.len())).map(|_| rng.gen::<Ext>()).collect();
        let z_index: Point<Ext> = (0..log_m + 1).map(|_| rng.gen::<Ext>()).collect();

        // Compute expected sum (shared reference value).
        let verifier_params = prover_params.clone().into_verifier_params::<Felt>();
        let expected_sum =
            verifier_params.full_jagged_little_polynomial_evaluation(&z_row, &z_col, &z_index);

        // --- CPU prover ---
        // Mirror the GPU's high-level fused flow: sample alpha, compute fused
        // claim, observe fused claim, then run the inner sumcheck. The GPU's
        // `prove_jagged_evaluation_sync` does the exact same dance so the FS
        // states stay in lockstep across the two impls.
        let mut cpu_challenger = SP1GlobalContext::default_challenger();
        let combine_alpha: Ext = cpu_challenger.sample_ext_element();
        let num_real_pairs = prefix_sums.len() - 1;
        let sum_z_first_n: Ext = sum_z_first_n_via_geq::<Felt, Ext>(num_real_pairs, &z_col);
        let fused_claim = expected_sum + combine_alpha * sum_z_first_n;
        cpu_challenger.observe_ext_element(fused_claim);

        let cpu_poly = JaggedEvalSumcheckPoly::<Felt, Ext>::new_from_jagged_params(
            z_row.clone(),
            z_col.clone(),
            z_index.clone(),
            prefix_sums.clone(),
            combine_alpha,
        );
        let mut cpu_sum_values = Buffer::from(vec![Ext::zero(); 6 * (log_m + 1)]);
        let cpu_proof = prove_jagged_eval_sumcheck(
            cpu_poly,
            &mut cpu_challenger,
            fused_claim,
            1,
            &mut cpu_sum_values,
        );

        // --- GPU prover ---
        let mut gpu_host_challenger = SP1GlobalContext::default_challenger();
        let gpu_proof = sp1_gpu_cudart::run_sync_in_place(|backend| {
            prove_jagged_evaluation_sync::<HostChallenger, DeviceChallenger>(
                &prover_params,
                &z_row,
                &z_col,
                &z_index,
                &mut gpu_host_challenger,
                expected_sum,
                &backend,
            )
        })
        .unwrap();
        let gpu_proof = gpu_proof.partial_sumcheck_proof;

        // --- Compare proofs ---
        assert_eq!(cpu_proof.claimed_sum, gpu_proof.claimed_sum, "Claimed sums differ");

        assert_eq!(
            cpu_proof.univariate_polys.len(),
            gpu_proof.univariate_polys.len(),
            "Number of rounds differ"
        );

        for (i, (cpu_poly, gpu_poly)) in
            cpu_proof.univariate_polys.iter().zip(gpu_proof.univariate_polys.iter()).enumerate()
        {
            assert_eq!(
                cpu_poly.coefficients, gpu_poly.coefficients,
                "Univariate polynomial coefficients differ at round {i}"
            );
        }

        assert_eq!(
            cpu_proof.point_and_eval, gpu_proof.point_and_eval,
            "Final point and eval differ"
        );
    }
}
