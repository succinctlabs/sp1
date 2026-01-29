//! Sync versions of jagged eval sumcheck for GPU (TaskScope).
//! These avoid the async trait overhead since GPU operations are already sync.

use std::sync::Arc;

use itertools::Itertools;
use slop_algebra::{interpolate_univariate_polynomial, ExtensionField, Field};
use slop_alloc::Buffer;
use slop_challenger::FieldChallenger;
use slop_jagged::{
    JaggedEvalSumcheckPoly, JaggedLittlePolynomialProverParams, JaggedSumcheckEvalProof,
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

/// Sync version of JaggedEvalSumcheckPoly::new_from_jagged_params for TaskScope.
/// Uses DeviceBuffer::from_host() for sync device copies.
#[allow(clippy::type_complexity)]
pub fn new_jagged_eval_sumcheck_poly_sync<F, EF, HostChallenger, DeviceChallenger>(
    z_row: Point<EF>,
    z_col: Point<EF>,
    z_index: Point<EF>,
    prefix_sums: Vec<usize>,
    backend: &TaskScope,
) -> JaggedEvalSumcheckPoly<
    F,
    EF,
    HostChallenger,
    DeviceChallenger,
    JaggedAssistSumAsPolyGPUImpl<F, EF, DeviceChallenger>,
    TaskScope,
>
where
    F: Field,
    EF: ExtensionField<F>,
    HostChallenger: FieldChallenger<F> + Send + Sync,
    DeviceChallenger: AsMutRawChallenger + Send + Sync + Clone,
    TaskScope: BranchingProgramKernel<F, EF, DeviceChallenger>
        + DeviceSumKernel<EF>
        + DeviceTransposeKernel<F>,
{
    let log_m = log2_ceil_usize(*prefix_sums.last().unwrap());
    let col_prefix_sums: Vec<Point<F>> =
        prefix_sums.iter().map(|&x| Point::from_usize(x, log_m + 1)).collect();

    // Generate all of the merged prefix sums
    let merged_prefix_sums: Vec<Point<F>> = col_prefix_sums
        .windows(2)
        .map(|prefix_sums| {
            let mut merged_prefix_sum = prefix_sums[0].clone();
            merged_prefix_sum.extend(&prefix_sums[1]);
            merged_prefix_sum
        })
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

    // Create the GPU implementation sync
    let bp_batch_eval = JaggedAssistSumAsPolyGPUImpl::new(
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

    JaggedEvalSumcheckPoly::new(
        bp_batch_eval,
        Point::new(Buffer::with_capacity_in(0, backend.clone())),
        z_col_device,
        merged_prefix_sums_device,
        z_col_eq_vals_device,
        0,
        intermediate_eq_full_evals_device,
        half,
        num_variables as u32,
    )
}

/// Sync version of prove_jagged_eval_sumcheck for TaskScope.
/// Calls sync methods directly instead of using async/.await.
pub fn prove_jagged_eval_sumcheck_sync<F, EF, HostChallenger, DeviceChallenger>(
    mut poly: JaggedEvalSumcheckPoly<
        F,
        EF,
        HostChallenger,
        DeviceChallenger,
        JaggedAssistSumAsPolyGPUImpl<F, EF, DeviceChallenger>,
        TaskScope,
    >,
    challenger: &mut DeviceChallenger,
    claim: EF,
    t: usize,
    sum_values: &mut Buffer<EF, TaskScope>,
) -> PartialSumcheckProof<EF>
where
    F: Field,
    EF: ExtensionField<F> + Send + Sync,
    HostChallenger: FieldChallenger<F> + Send + Sync,
    DeviceChallenger: AsMutRawChallenger + Send + Sync + Clone,
    TaskScope: BranchingProgramKernel<F, EF, DeviceChallenger>
        + DeviceSumKernel<EF>
        + DeviceTransposeKernel<F>,
{
    let num_variables = poly.num_variables();

    // First round of sumcheck - sync call
    let (mut round_claim, new_point) = poly.bp_batch_eval.sum_as_poly_and_sample_into_point(
        poly.round_num,
        &poly.z_col_eq_vals,
        &poly.intermediate_eq_full_evals,
        sum_values,
        challenger,
        claim,
        poly.rho.clone(),
    );
    poly.rho = new_point;

    // Fix last variable - sync call
    JaggedAssistSumAsPolyGPUImpl::<F, EF, DeviceChallenger>::fix_last_variable_kernel::<
        DeviceChallenger,
    >(
        &poly.merged_prefix_sums,
        &mut poly.intermediate_eq_full_evals,
        &poly.rho,
        poly.prefix_sum_dimension as usize,
        poly.round_num,
    );
    poly.round_num += 1;

    for _ in t..num_variables as usize {
        let (new_claim, new_point) = poly.bp_batch_eval.sum_as_poly_and_sample_into_point(
            poly.round_num,
            &poly.z_col_eq_vals,
            &poly.intermediate_eq_full_evals,
            sum_values,
            challenger,
            round_claim,
            poly.rho.clone(),
        );
        round_claim = new_claim;
        poly.rho = new_point;

        JaggedAssistSumAsPolyGPUImpl::<F, EF, DeviceChallenger>::fix_last_variable_kernel::<
            DeviceChallenger,
        >(
            &poly.merged_prefix_sums,
            &mut poly.intermediate_eq_full_evals,
            &poly.rho,
            poly.prefix_sum_dimension as usize,
            poly.round_num,
        );
        poly.round_num += 1;
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
    // Create sumcheck poly sync
    let jagged_eval_sc_poly =
        new_jagged_eval_sumcheck_poly_sync::<F, EF, HostChallenger, DeviceChallenger>(
            z_row.clone(),
            z_col.clone(),
            z_trace.clone(),
            params.col_prefix_sums_usize.clone(),
            backend,
        );

    // Compute expected sum
    let verifier_params = params.clone().into_verifier_params();
    let expected_sum =
        verifier_params.full_jagged_little_polynomial_evaluation(z_row, z_col, z_trace);

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
