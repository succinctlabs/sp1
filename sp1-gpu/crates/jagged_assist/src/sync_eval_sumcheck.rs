//! Sync versions of jagged eval sumcheck for GPU (TaskScope).
//! These avoid the async trait overhead since GPU operations are already sync.

use std::sync::Arc;

use itertools::Itertools;
use slop_algebra::{interpolate_univariate_polynomial, ExtensionField, Field};
use slop_alloc::Buffer;
use slop_challenger::FieldChallenger;
use slop_jagged::{
    interleave_prefix_sums, JaggedLittlePolynomialProverParams, JaggedSumcheckEvalProof,
};
use slop_multilinear::{Mle, Point};
use slop_sumcheck::PartialSumcheckProof;
use slop_tensor::Tensor;
use sp1_gpu_challenger::FromHostChallengerSync;
use sp1_gpu_cudart::reduce::DeviceSumKernel;
use sp1_gpu_cudart::transpose::DeviceTransposeKernel;
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
    pub merged_prefix_sums: Buffer<F, TaskScope>,
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

    /// Fix the last variable by updating intermediate eq evals via GPU kernel.
    pub fn fix_last_variable(&mut self)
    where
        DeviceChallenger: AsMutRawChallenger,
        TaskScope: BranchingProgramKernel<F, EF, DeviceChallenger>
            + DeviceSumKernel<EF>
            + DeviceTransposeKernel<F>,
    {
        JaggedAssistSumAsPolyGPUImpl::<F, EF, DeviceChallenger>::fix_last_variable_kernel::<
            DeviceChallenger,
        >(
            &self.merged_prefix_sums,
            &mut self.intermediate_eq_full_evals,
            &self.rho,
            self.prefix_sum_dimension as usize,
            self.round_num,
        );
        self.round_num += 1;
    }
}

/// Construct a `JaggedEvalSumcheckPolyGPU` from jagged params, with all data on device.
/// Returns `(poly, expected_sum)` where `expected_sum` is the full jagged little polynomial
/// evaluation, computed on the GPU during prefix state precomputation.
#[allow(clippy::type_complexity)]
pub fn new_jagged_eval_sumcheck_poly_sync<F, EF, DeviceChallenger>(
    z_row: Point<EF>,
    z_col: Point<EF>,
    z_index: Point<EF>,
    prefix_sums: Vec<usize>,
    backend: &TaskScope,
) -> (JaggedEvalSumcheckPolyGPU<F, EF, DeviceChallenger>, EF)
where
    F: Field,
    EF: ExtensionField<F>,
    DeviceChallenger: AsMutRawChallenger + Send + Sync + Clone,
    TaskScope: BranchingProgramKernel<F, EF, DeviceChallenger>
        + DeviceSumKernel<EF>
        + DeviceTransposeKernel<F>,
{
    let log_m = log2_ceil_usize(*prefix_sums.last().unwrap());
    let col_prefix_sums: Vec<Point<F>> =
        prefix_sums.iter().map(|&x| Point::from_usize(x, log_m + 1)).collect();

    // Generate all of the merged prefix sums in interleaved layout:
    // [next[MSB], curr[MSB], next[MSB-1], curr[MSB-1], ..., next[LSB], curr[LSB]]
    let merged_prefix_sums: Vec<Point<F>> = col_prefix_sums
        .windows(2)
        .map(|prefix_sums| interleave_prefix_sums(&prefix_sums[0], &prefix_sums[1]))
        .collect();

    // Generate z_col partial lagrange mle
    let z_col_partial_lagrange = Mle::blocking_partial_lagrange(&z_col);

    // Condense merged_prefix_sums and z_col_eq_vals for empty tables
    let (merged_prefix_sums, z_col_eq_vals): (Vec<Point<F>>, Vec<EF>) = merged_prefix_sums
        .iter()
        .zip(z_col_partial_lagrange.guts().as_slice())
        .chunk_by(|(merged_prefix_sum, _)| *merged_prefix_sum)
        .into_iter()
        .map(|(merged_prefix_sum, group)| {
            let group_elements =
                group.into_iter().map(|(_, z_col_eq_val)| *z_col_eq_val).collect_vec();
            (merged_prefix_sum.clone(), group_elements.into_iter().sum::<EF>())
        })
        .unzip();

    let merged_prefix_sums_len = merged_prefix_sums.len();
    let num_variables = merged_prefix_sums[0].dimension();
    assert!(merged_prefix_sums_len == z_col_eq_vals.len());

    let merged_prefix_sums = Arc::new(merged_prefix_sums);

    // Sync device copy for z_col
    let z_col_buffer: Buffer<EF> = z_col.to_vec().into();
    let z_col_device: Point<EF, TaskScope> =
        Point::new(DeviceBuffer::from_host(&z_col_buffer, backend).unwrap().into_inner());

    let half = EF::two().inverse();

    // Create the GPU implementation sync (also computes expected_sum from prefix states)
    let (bp_batch_eval, expected_sum) = JaggedAssistSumAsPolyGPUImpl::new(
        z_row,
        z_index,
        &merged_prefix_sums,
        &z_col_eq_vals,
        backend,
    );

    // Sync device copies
    let z_col_eq_vals_buffer = Buffer::<EF>::from(z_col_eq_vals);
    let z_col_eq_vals_device =
        DeviceBuffer::from_host(&z_col_eq_vals_buffer, backend).unwrap().into_inner();

    let merged_prefix_sums_flat: Buffer<F> =
        merged_prefix_sums.iter().flat_map(|point| point.iter()).copied().collect();
    let merged_prefix_sums_device =
        DeviceBuffer::from_host(&merged_prefix_sums_flat, backend).unwrap().into_inner();

    let intermediate_eq_full_evals = vec![EF::one(); merged_prefix_sums_len];
    let intermediate_eq_full_evals_buffer = Buffer::<EF>::from(intermediate_eq_full_evals);
    let intermediate_eq_full_evals_device =
        DeviceBuffer::from_host(&intermediate_eq_full_evals_buffer, backend).unwrap().into_inner();

    (
        JaggedEvalSumcheckPolyGPU {
            bp_batch_eval,
            rho: Point::new(Buffer::with_capacity_in(0, backend.clone())),
            z_col: z_col_device,
            merged_prefix_sums: merged_prefix_sums_device,
            z_col_eq_vals: z_col_eq_vals_device,
            round_num: 0,
            intermediate_eq_full_evals: intermediate_eq_full_evals_device,
            half,
            prefix_sum_dimension: num_variables as u32,
        },
        expected_sum,
    )
}

/// Sync version of prove_jagged_eval_sumcheck for TaskScope.
/// Calls sync methods directly instead of using async/.await.
pub fn prove_jagged_eval_sumcheck_sync<F, EF, DeviceChallenger>(
    mut poly: JaggedEvalSumcheckPolyGPU<F, EF, DeviceChallenger>,
    challenger: &mut DeviceChallenger,
    claim: EF,
    t: usize,
    sum_values: &mut Buffer<EF, TaskScope>,
) -> PartialSumcheckProof<EF>
where
    F: Field,
    EF: ExtensionField<F> + Send + Sync,
    DeviceChallenger: AsMutRawChallenger + Send + Sync + Clone,
    TaskScope: BranchingProgramKernel<F, EF, DeviceChallenger>
        + DeviceSumKernel<EF>
        + DeviceTransposeKernel<F>,
{
    let num_variables = poly.num_variables();

    // First round of sumcheck - sync call
    poly.rho = poly.bp_batch_eval.sum_as_poly_and_sample_into_point(
        poly.round_num,
        &poly.z_col_eq_vals,
        &poly.intermediate_eq_full_evals,
        sum_values,
        challenger,
        poly.rho.clone(),
    );

    // Fix last variable
    poly.fix_last_variable();

    for _ in t..num_variables as usize {
        poly.rho = poly.bp_batch_eval.sum_as_poly_and_sample_into_point(
            poly.round_num,
            &poly.z_col_eq_vals,
            &poly.intermediate_eq_full_evals,
            sum_values,
            challenger,
            poly.rho.clone(),
        );

        poly.fix_last_variable();
    }

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

    // Move randomness point to CPU
    let point_host = unsafe { poly.rho.values().copy_into_host_vec() };

    let final_claim: EF =
        univariate_polys.last().unwrap().eval_at_point(point_host.first().copied().unwrap());

    PartialSumcheckProof {
        univariate_polys,
        claimed_sum: claim,
        point_and_eval: (point_host.into(), final_claim),
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
    backend: &TaskScope,
) -> JaggedSumcheckEvalProof<EF>
where
    F: Field,
    EF: ExtensionField<F> + Send + Sync,
    HostChallenger: FieldChallenger<F> + Send + Sync,
    DeviceChallenger:
        AsMutRawChallenger + FromHostChallengerSync<HostChallenger> + Clone + Send + Sync,
    TaskScope: BranchingProgramKernel<F, EF, DeviceChallenger>
        + DeviceSumKernel<EF>
        + DeviceTransposeKernel<F>,
{
    // Create sumcheck poly sync (also computes expected_sum from GPU prefix states)
    let (jagged_eval_sc_poly, expected_sum) =
        new_jagged_eval_sumcheck_poly_sync::<F, EF, DeviceChallenger>(
            z_row.clone(),
            z_col.clone(),
            z_trace.clone(),
            params.col_prefix_sums_usize.clone(),
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
    use slop_koala_bear::{KoalaBearDegree4Duplex, KoalaPerm};
    use slop_multilinear::Point;
    use sp1_gpu_challenger::DuplexChallenger as DeviceDuplexChallenger;
    use sp1_gpu_cudart::TaskScope;
    use sp1_primitives::{SP1ExtensionField, SP1Field};

    type F = SP1Field;
    type EF = SP1ExtensionField;
    type HostChallenger = slop_challenger::DuplexChallenger<F, KoalaPerm, 16, 8>;
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
        let mut cpu_challenger = KoalaBearDegree4Duplex::default_challenger();
        cpu_challenger.observe_ext_element(expected_sum);

        let cpu_poly = JaggedEvalSumcheckPoly::<F, EF, HostChallenger>::new_from_jagged_params(
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
        let mut gpu_host_challenger = KoalaBearDegree4Duplex::default_challenger();
        let gpu_proof = sp1_gpu_cudart::run_sync_in_place(|backend| {
            prove_jagged_evaluation_sync::<F, EF, HostChallenger, DeviceChallenger>(
                &prover_params,
                &z_row,
                &z_col,
                &z_index,
                &mut gpu_host_challenger,
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
