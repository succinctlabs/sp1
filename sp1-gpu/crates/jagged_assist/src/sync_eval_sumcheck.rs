//! Sync versions of jagged eval sumcheck for GPU (TaskScope).
//! These avoid the async trait overhead since GPU operations are already sync.

use slop_algebra::{interpolate_univariate_polynomial, ExtensionField, Field};
use slop_alloc::Buffer;
use slop_challenger::FieldChallenger;
use slop_jagged::{JaggedLittlePolynomialProverParams, JaggedSumcheckEvalProof};
use slop_multilinear::{Mle, Point};
use slop_sumcheck::PartialSumcheckProof;
use slop_tensor::Tensor;
use sp1_gpu_challenger::FromHostChallengerSync;
use sp1_gpu_cudart::reduce::DeviceSumKernel;
use sp1_gpu_cudart::{DeviceBuffer, TaskScope};

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
pub struct JaggedEvalSumcheckPolyGPU<F: Field, EF: ExtensionField<F>, DeviceChallenger> {
    pub bp_batch_eval: JaggedAssistSumAsPolyGPUImpl<F, EF, DeviceChallenger>,
    pub rho: Point<EF, TaskScope>,
    pub z_col: Point<EF, TaskScope>,
    pub z_col_eq_vals: Buffer<EF, TaskScope>,
    pub round_num: usize,
    pub intermediate_eq_full_evals: Buffer<EF, TaskScope>,
    pub half: EF,
    pub prefix_sum_dimension: u32,
}

impl<F: Field, EF: ExtensionField<F>, DeviceChallenger>
    JaggedEvalSumcheckPolyGPU<F, EF, DeviceChallenger>
{
    pub fn num_variables(&self) -> u32 {
        self.prefix_sum_dimension
    }
}

/// Construct a `JaggedEvalSumcheckPolyGPU` from jagged params, with all data on device.
pub fn new_jagged_eval_sumcheck_poly_sync<F, EF, DeviceChallenger>(
    z_row: Point<EF>,
    z_col: Point<EF>,
    z_index: Point<EF>,
    prefix_sums: Vec<usize>,
    expected_sum: EF,
    backend: &TaskScope,
) -> JaggedEvalSumcheckPolyGPU<F, EF, DeviceChallenger>
where
    F: Field,
    EF: ExtensionField<F>,
    DeviceChallenger: AsMutRawChallenger + Send + Sync + Clone,
    TaskScope: BranchingProgramKernel<F, EF, DeviceChallenger> + DeviceSumKernel<EF>,
{
    let prefix_sum_length = log2_ceil_usize(*prefix_sums.last().unwrap()) + 1;

    let z_col_partial_lagrange = Mle::blocking_partial_lagrange(&z_col);
    let z_col_lagrange = z_col_partial_lagrange.guts().as_slice();

    // Condense `(curr, next)` prefix-sum pairs by collapsing runs of identical
    // adjacent pairs (= empty-trace columns) and summing their z_col eq values.
    // Each kept pair contributes one column to the BP eval.
    let mut prefix_sum_pairs: Vec<(usize, usize)> = Vec::with_capacity(prefix_sums.len() - 1);
    let mut z_col_eq_vals: Vec<EF> = Vec::with_capacity(prefix_sums.len() - 1);
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
    let z_col_buffer: Buffer<EF> = z_col.to_vec().into();
    let z_col_device: Point<EF, TaskScope> =
        Point::new(DeviceBuffer::from_host(&z_col_buffer, backend).unwrap().into_inner());

    let half = EF::two().inverse();

    let bp_batch_eval = JaggedAssistSumAsPolyGPUImpl::new(
        z_row,
        z_index,
        &prefix_sum_pairs,
        prefix_sum_length,
        expected_sum,
        backend,
    );

    let z_col_eq_vals_buffer = Buffer::<EF>::from(z_col_eq_vals);
    let z_col_eq_vals_device =
        DeviceBuffer::from_host(&z_col_eq_vals_buffer, backend).unwrap().into_inner();

    let intermediate_eq_full_evals = vec![EF::one(); num_columns];
    let intermediate_eq_full_evals_buffer = Buffer::<EF>::from(intermediate_eq_full_evals);
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
pub fn prove_jagged_eval_sumcheck_sync<F, EF, DeviceChallenger>(
    mut poly: JaggedEvalSumcheckPolyGPU<F, EF, DeviceChallenger>,
    challenger: &mut DeviceChallenger,
    claim: EF,
    _t: usize,
    sum_values: &mut Buffer<EF, TaskScope>,
) -> PartialSumcheckProof<EF>
where
    F: Field,
    EF: ExtensionField<F> + Send + Sync,
    DeviceChallenger: AsMutRawChallenger + Send + Sync + Clone,
    TaskScope: BranchingProgramKernel<F, EF, DeviceChallenger> + DeviceSumKernel<EF>,
{
    let num_variables = poly.num_variables() as usize;

    // Single fused cooperative kernel launch for all rounds
    let rho_buffer = poly.bp_batch_eval.fused_sumcheck(
        num_variables,
        &poly.z_col_eq_vals,
        &mut poly.intermediate_eq_full_evals,
        sum_values,
        challenger,
    );

    // Move sum_as_poly evaluations to CPU
    let host_sum_values = unsafe { sum_values.copy_into_host_vec() };

    let univariate_polys = host_sum_values
        .as_slice()
        .chunks_exact(3)
        .map(|chunk| {
            let ys: [EF; 3] = chunk.try_into().unwrap();
            let xs: [EF; 3] = [EF::zero(), EF::two().inverse(), EF::one()];
            interpolate_univariate_polynomial(&xs, &ys)
        })
        .collect::<Vec<_>>();

    // Move rho_buffer to CPU and reverse (kernel writes forward, convention is reversed)
    let mut rho_host = unsafe { rho_buffer.copy_into_host_vec() };
    rho_host.reverse();

    let final_claim: EF =
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
pub fn prove_jagged_evaluation_sync<F, EF, HostChallenger, DeviceChallenger>(
    params: &JaggedLittlePolynomialProverParams,
    z_row: &Point<EF>,
    z_col: &Point<EF>,
    z_trace: &Point<EF>,
    challenger: &mut HostChallenger,
    expected_sum: EF,
    backend: &TaskScope,
) -> JaggedSumcheckEvalProof<EF>
where
    F: Field,
    EF: ExtensionField<F> + Send + Sync,
    HostChallenger: FieldChallenger<F> + Send + Sync,
    DeviceChallenger:
        AsMutRawChallenger + FromHostChallengerSync<HostChallenger> + Clone + Send + Sync,
    TaskScope: BranchingProgramKernel<F, EF, DeviceChallenger> + DeviceSumKernel<EF>,
{
    let jagged_eval_sc_poly = new_jagged_eval_sumcheck_poly_sync::<F, EF, DeviceChallenger>(
        z_row.clone(),
        z_col.clone(),
        z_trace.clone(),
        params.col_prefix_sums_usize.clone(),
        expected_sum,
        backend,
    );

    let log_m = log2_ceil_usize(*params.col_prefix_sums_usize.last().unwrap());

    let mut sum_values = Tensor::zeros_in([3, 2 * (log_m + 1)], backend.clone()).into_buffer();

    challenger.observe_ext_element(expected_sum);

    // Create device challenger sync
    let mut device_challenger = DeviceChallenger::from_host_challenger_sync(challenger, backend);

    // Run sumcheck sync
    let partial_sumcheck_proof = prove_jagged_eval_sumcheck_sync(
        jagged_eval_sc_poly,
        &mut device_challenger,
        expected_sum,
        1,
        &mut sum_values,
    );

    // Sync CPU challenger with device challenger state
    for poly in &partial_sumcheck_proof.univariate_polys {
        // Inline observe_constant_length_extension_slice to avoid VariableLengthChallenger bound
        for &coeff in &poly.coefficients {
            challenger.observe_ext_element(coeff);
        }
        let _: EF = challenger.sample_ext_element();
    }

    JaggedSumcheckEvalProof { partial_sumcheck_proof }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use slop_algebra::AbstractField;
    use slop_alloc::Buffer;
    use slop_challenger::{FieldChallenger, IopCtx};
    use slop_jagged::{
        prove_jagged_eval_sumcheck, JaggedEvalSumcheckPoly, JaggedLittlePolynomialProverParams,
    };
    use slop_multilinear::Point;
    use sp1_gpu_challenger::DuplexChallenger as DeviceDuplexChallenger;
    use sp1_gpu_cudart::TaskScope;
    use sp1_primitives::{SP1ExtensionField, SP1Field, SP1GlobalContext, SP1Perm};

    type F = SP1Field;
    type EF = SP1ExtensionField;
    type HostChallenger = slop_challenger::DuplexChallenger<F, SP1Perm, 16, 8>;
    type DeviceChallenger = DeviceDuplexChallenger<F, TaskScope>;

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

        let z_row: Point<EF> = (0..log_max_row_count).map(|_| rng.gen::<EF>()).collect();
        let z_col: Point<EF> =
            (0..log2_ceil_usize(row_counts.len())).map(|_| rng.gen::<EF>()).collect();
        let z_index: Point<EF> = (0..log_m + 1).map(|_| rng.gen::<EF>()).collect();

        // Compute expected sum (shared reference value).
        let verifier_params = prover_params.clone().into_verifier_params::<F>();
        let expected_sum =
            verifier_params.full_jagged_little_polynomial_evaluation(&z_row, &z_col, &z_index);

        // --- CPU prover ---
        let mut cpu_challenger = SP1GlobalContext::default_challenger();
        cpu_challenger.observe_ext_element(expected_sum);

        let cpu_poly = JaggedEvalSumcheckPoly::<F, EF>::new_from_jagged_params(
            z_row.clone(),
            z_col.clone(),
            z_index.clone(),
            prefix_sums.clone(),
        );
        let mut cpu_sum_values = Buffer::from(vec![EF::zero(); 6 * (log_m + 1)]);
        let cpu_proof = prove_jagged_eval_sumcheck(
            cpu_poly,
            &mut cpu_challenger,
            expected_sum,
            1,
            &mut cpu_sum_values,
        );

        // --- GPU prover ---
        let mut gpu_host_challenger = SP1GlobalContext::default_challenger();
        let gpu_proof = sp1_gpu_cudart::run_sync_in_place(|backend| {
            prove_jagged_evaluation_sync::<F, EF, HostChallenger, DeviceChallenger>(
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
