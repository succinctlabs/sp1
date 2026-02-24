use sp1_gpu_cudart::{
    args,
    sys::v2_kernels::{
        jagged_fix_and_sum, jagged_sum_as_poly,
        mle_fix_last_variable_koala_bear_ext_ext_zero_padding, padded_hadamard_fix_and_sum,
    },
    DeviceMle, DeviceTensor, TaskScope,
};

use itertools::Itertools;
use slop_algebra::{
    interpolate_univariate_polynomial, AbstractExtensionField, AbstractField, Field,
    UnivariatePolynomial,
};
use slop_alloc::{Backend, HasBackend};
use slop_challenger::FieldChallenger;
use slop_multilinear::Mle;
use slop_sumcheck::PartialSumcheckProof;
use slop_tensor::Tensor;

use sp1_gpu_utils::{DenseData, Ext, Felt, JaggedTraceMle};

use super::hadamard::{fix_last_variable, fix_last_variable_and_sum_as_poly};

/// The polynomial for the first round of the jagged sumcheck.
///
/// eq_z_col and eq_z_row are stored individually to save memory. In future smaller rounds,
/// they are combined.
pub struct JaggedFirstRoundPoly<'a, A: Backend = TaskScope> {
    pub base: &'a JaggedTraceMle<Felt, A>,
    pub eq_z_col: Mle<Ext, A>,
    pub eq_z_row: Mle<Ext, A>,
    pub height: usize,
    pub total_number_of_variables: u32,
}

impl<'a, A: Backend> JaggedFirstRoundPoly<'a, A> {
    #[inline]
    pub fn new(
        base: &'a JaggedTraceMle<Felt, A>,
        eq_z_col: Mle<Ext, A>,
        eq_z_row: Mle<Ext, A>,
        height: usize,
    ) -> Self {
        let total_number_of_variables = (base.dense().dense.len()).next_power_of_two().ilog2();
        Self { base, eq_z_col, eq_z_row, height, total_number_of_variables }
    }

    /// # Safety
    ///
    /// See [std::mem::MaybeUninit::assume_init].
    #[inline]
    pub unsafe fn assume_init(&mut self) {
        self.eq_z_col.assume_init();
        self.eq_z_row.assume_init();
    }
}

#[repr(C)]
pub struct JaggedFirstRoundPolyRaw {
    col_index: *const u32,
    start_indices: *const u32,
    base: *const Felt,
    eq_z_col: *const Ext,
    eq_z_row: *const Ext,
    height: usize,
}

#[repr(C)]
pub struct JaggedFirstRoundPolyMutRaw {
    base: *mut Felt,
    eq_z_col: *mut Ext,
    eq_z_row: *mut Ext,
    height: usize,
}

impl<'a, A: Backend> DenseData<A> for JaggedFirstRoundPoly<'a, A> {
    type DenseDataRaw = JaggedFirstRoundPolyRaw;
    fn as_ptr(&self) -> Self::DenseDataRaw {
        JaggedFirstRoundPolyRaw {
            col_index: self.base.col_index.as_ptr(),
            start_indices: self.base.start_indices.as_ptr(),
            base: self.base.dense().dense.as_ptr(),
            eq_z_col: self.eq_z_col.guts().as_ptr(),
            eq_z_row: self.eq_z_row.guts().as_ptr(),
            height: self.height,
        }
    }
}

/// Generates the first round jagged poly from traces, eq_z_col, and eq_z_row.  
pub fn generate_jagged_sumcheck_poly(
    traces: &'_ JaggedTraceMle<Felt, TaskScope>,
    eq_z_col: DeviceMle<Ext>,
    eq_z_row: DeviceMle<Ext>,
) -> JaggedFirstRoundPoly<'_> {
    let half_len = traces.dense().dense.len() >> 1;
    JaggedFirstRoundPoly::new(traces, eq_z_col.into(), eq_z_row.into(), half_len)
}

/// Get the first univariate message for the jagged sumcheck.
fn sum_as_poly_first_round<'a>(
    poly: &JaggedFirstRoundPoly<'a>,
    claim: Ext,
) -> UnivariatePolynomial<Ext> {
    let circuit = &poly;

    let height = circuit.height;

    let backend = circuit.base.backend();

    const BLOCK_SIZE: usize = 256;
    const STRIDE: usize = 32;

    let grid_dim = height.div_ceil(BLOCK_SIZE).div_ceil(STRIDE);
    let mut output = Tensor::<Ext, TaskScope>::with_sizes_in([2, grid_dim], backend.clone());

    let num_tiles = BLOCK_SIZE.checked_div(STRIDE).unwrap_or(1);
    let shared_mem = num_tiles * std::mem::size_of::<Ext>();

    unsafe {
        output.assume_init();
        let args = args!(output.as_mut_ptr(), circuit.as_ptr());
        backend
            .launch_kernel(jagged_sum_as_poly(), grid_dim, BLOCK_SIZE, &args, shared_mem)
            .unwrap();
    }

    let output = DeviceTensor::from_raw(output);
    let tensor = output.sum_dim(1).to_host().unwrap();
    let [eval_zero, eval_half] = tensor.as_slice().try_into().unwrap();

    let eval_one = claim - eval_zero;

    interpolate_univariate_polynomial(
        &[
            Ext::from_canonical_u16(0),
            Ext::from_canonical_u16(1),
            Ext::from_canonical_u16(2).inverse(),
        ],
        &[eval_zero, eval_one, eval_half * Ext::from_canonical_u16(4).inverse()],
    )
}

/// Fix the last variable of the first gkr layer.
fn fix_and_sum_first_round<'a>(
    poly: JaggedFirstRoundPoly<'a>,
    alpha: Ext,
    claim: Ext,
) -> (UnivariatePolynomial<Ext>, Mle<Ext, TaskScope>, Mle<Ext, TaskScope>) {
    let backend = poly.base.backend();
    let height = poly.height;

    // Create a new layer
    let mut output_p: Tensor<Ext, TaskScope> = Tensor::with_sizes_in([1, height], backend.clone());
    let mut output_q: Tensor<Ext, TaskScope> = Tensor::with_sizes_in([1, height], backend.clone());

    // Populate the new layer
    const BLOCK_SIZE: usize = 256;
    const STRIDE: usize = 32;
    let grid_size_x = height.div_ceil(BLOCK_SIZE * STRIDE * 2); // * 2 because we are doing 2 fixes per thread.
    let mut evaluations =
        Tensor::<Ext, TaskScope>::with_sizes_in([2, grid_size_x], backend.clone());
    let grid_size = (grid_size_x, 1, 1);
    let block_dim = BLOCK_SIZE;

    let num_tiles = BLOCK_SIZE.checked_div(STRIDE).unwrap_or(1);
    let shared_mem = num_tiles * std::mem::size_of::<Ext>();

    unsafe {
        output_p.assume_init();
        output_q.assume_init();
        evaluations.assume_init();
        let args = args!(
            evaluations.as_mut_ptr(),
            poly.as_ptr(),
            output_p.as_mut_ptr(),
            output_q.as_mut_ptr(),
            alpha
        );
        backend
            .launch_kernel(jagged_fix_and_sum(), grid_size, block_dim, &args, shared_mem)
            .unwrap();
    }

    // Sum the evaluations across all dimensions.
    let evaluations = DeviceTensor::from_raw(evaluations);
    let evaluations = evaluations.sum_dim(1).to_host().unwrap();
    let [eval_zero, eval_half] = evaluations.as_slice().try_into().unwrap();

    let eval_one = claim - eval_zero;

    let uni_poly = interpolate_univariate_polynomial(
        &[
            Ext::from_canonical_u16(0),
            Ext::from_canonical_u16(1),
            Ext::from_canonical_u16(2).inverse(),
        ],
        &[eval_zero, eval_one, eval_half * Ext::from_canonical_u16(4).inverse()],
    );

    (uni_poly, Mle::new(output_p), Mle::new(output_q))
}

/// Process a univariate polynomial by observing it with the challenger and sampling the next evaluation point
#[inline]
fn process_univariate_polynomial<C>(
    uni_poly: UnivariatePolynomial<Ext>,
    challenger: &mut C,
    univariate_poly_msgs: &mut Vec<UnivariatePolynomial<Ext>>,
    point: &mut Vec<Ext>,
) -> Ext
where
    C: FieldChallenger<Felt>,
{
    let coefficients =
        uni_poly.coefficients.iter().flat_map(|x| x.as_base_slice()).copied().collect_vec();
    challenger.observe_slice(&coefficients);
    univariate_poly_msgs.push(uni_poly);
    let alpha: Ext = challenger.sample_ext_element();
    point.insert(0, alpha);
    alpha
}

/// Performs the jagged sumcheck, outputting the sumcheck proof and evaluations.
pub fn jagged_sumcheck<C>(
    poly: JaggedFirstRoundPoly<'_>,
    challenger: &mut C,
    claim: Ext,
) -> (PartialSumcheckProof<Ext>, Vec<Ext>)
where
    C: FieldChallenger<Felt>,
{
    let num_variables = poly.total_number_of_variables;

    assert!(num_variables >= 1_u32);

    let mut point = vec![];

    let mut univariate_poly_msgs: Vec<UnivariatePolynomial<Ext>> = vec![];

    let uni_poly = sum_as_poly_first_round(&poly, claim);

    let alpha =
        process_univariate_polynomial(uni_poly, challenger, &mut univariate_poly_msgs, &mut point);
    let round_claim = univariate_poly_msgs.last().unwrap().eval_at_point(alpha);

    let (mut uni_poly, mut p, mut q) = fix_and_sum_first_round(poly, alpha, round_claim);

    let mut alpha =
        process_univariate_polynomial(uni_poly, challenger, &mut univariate_poly_msgs, &mut point);

    for _ in 2..num_variables as usize {
        // Get the round claims from the last round's univariate poly messages.
        let round_claim = univariate_poly_msgs.last().unwrap().eval_at_point(alpha);

        (p, q, uni_poly) = fix_last_variable_and_sum_as_poly(
            p,
            q,
            alpha,
            round_claim,
            padded_hadamard_fix_and_sum,
        );

        alpha = process_univariate_polynomial(
            uni_poly,
            challenger,
            &mut univariate_poly_msgs,
            &mut point,
        );
    }

    let (p, q) =
        fix_last_variable(p, q, alpha, mle_fix_last_variable_koala_bear_ext_ext_zero_padding);

    let proof = PartialSumcheckProof {
        univariate_polys: univariate_poly_msgs.clone(),
        claimed_sum: claim,
        point_and_eval: (
            point.clone().into(),
            univariate_poly_msgs.last().unwrap().eval_at_point(alpha),
        ),
    };
    let p_eval_tensor = DeviceTensor::copy_to_host(p.guts()).unwrap();
    let p_eval = Ext::from_base(p_eval_tensor.as_slice()[0]);
    let q_eval_tensor = DeviceTensor::copy_to_host(q.guts()).unwrap();
    let q_eval = q_eval_tensor.as_slice()[0];

    (proof, vec![p_eval, q_eval])
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rand::{rngs::StdRng, SeedableRng as _};
    use rayon::iter::{IntoParallelIterator, ParallelIterator};
    use slop_algebra::AbstractExtensionField;
    use slop_challenger::IopCtx;
    use slop_multilinear::{Mle, MultilinearPcsChallenger};
    use slop_sumcheck::partially_verify_sumcheck_proof;
    use slop_tensor::Tensor;

    use sp1_gpu_cudart::{run_sync_in_place, DeviceBuffer, DeviceMle, DevicePoint, TaskScope};
    use sp1_gpu_tracing::init_tracer;
    use sp1_gpu_utils::{Ext, Felt, JaggedTraceMle, TestGC, TraceDenseData};

    use crate::sumcheck::{jagged_sumcheck, JaggedFirstRoundPoly};

    #[test]
    fn test_jagged_sumcheck_poly() {
        init_tracer();
        let mut rng = StdRng::seed_from_u64(2);

        // Source from an RSP block. Includes preprocessed row counts.
        let row_counts_1 = vec![
            65536_usize,
            472032,
            131072,
            4194304,
            115200,
            80736,
            1814464,
            11616,
            643776,
            997920,
            65536,
            0,
            408608,
            0,
            0,
            48128,
            79264,
            1041248,
            406880,
            0,
            2624,
            832,
            0,
            128,
            203072,
            2880,
            16,
            0,
            472032,
            131072,
            18688,
            28000,
            32,
            699040,
            376000,
            832,
            32,
            23200,
            832,
            2496,
            2496,
            56736,
            4194304,
            415328,
        ];

        let row_counts_2 = vec![
            65536_usize,
            472032,
            131072,
            4194304,
            115200,
            295040,
            1056352,
            11072,
            659168,
            1083552,
            65536,
            32,
            303168,
            0,
            0,
            21920,
            115712,
            977152,
            635040,
            256,
            1792,
            768,
            24896,
            128,
            150752,
            18944,
            16,
            0,
            472032,
            131072,
            442912,
            233728,
            32,
            348832,
            550656,
            736,
            2496,
            43968,
            960,
            1664,
            1696,
            59200,
            4194304,
            1277984,
        ];

        let column_counts = vec![
            7_usize, 16, 2, 0, 1, 34, 31, 37, 52, 46, 6, 247, 282, 61, 36, 32, 39, 49, 41, 46, 46,
            50, 45, 15, 20, 83, 60, 10, 1, 1, 66, 70, 14, 52, 41, 47, 46, 34, 33, 10, 68, 32, 0, 1,
        ];

        let test_cases = [(row_counts_1, column_counts.clone()), (row_counts_2, column_counts)];

        run_sync_in_place(|t| {
            for (i, (row_counts, column_counts)) in test_cases.iter().enumerate() {
                let mut challenger = TestGC::default_challenger();

                let log_max_row_count =
                    row_counts.iter().max().unwrap().next_power_of_two().ilog2();
                let num_col_variables =
                    column_counts.iter().sum::<usize>().next_power_of_two().ilog2();

                let z_row = challenger.sample_point::<Ext>(log_max_row_count);
                let z_col = challenger.sample_point::<Ext>(num_col_variables);

                tracing::info!("log max row count: {}", log_max_row_count);
                tracing::info!("num col variables: {}", num_col_variables);

                // Compute partial lagrange on CPU for verification.
                let eq_z_row_cpu = Mle::<Ext>::partial_lagrange(&z_row);
                let eq_z_col_cpu = Mle::<Ext>::partial_lagrange(&z_col);
                let eq_z_row_vec: Vec<Ext> = eq_z_row_cpu.guts().as_buffer().as_slice().to_vec();
                let eq_z_col_vec: Vec<Ext> = eq_z_col_cpu.guts().as_buffer().as_slice().to_vec();

                // Compute partial lagrange on GPU for the sumcheck.
                let d_z_row = DevicePoint::from_host(&z_row, &t).unwrap();
                let d_z_col = DevicePoint::from_host(&z_col, &t).unwrap();
                let eq_z_row_device = d_z_row.partial_lagrange();
                let eq_z_col_device = d_z_col.partial_lagrange();

                // Build trace structure.
                let mut dense_size = 0;
                let mut col_index_vec = Vec::new();
                let mut start_indices_vec = Vec::with_capacity(row_counts.len() + 1);
                let mut row = Vec::new();

                let mut columns_so_far = 0;
                for (row_count, column_count) in row_counts.iter().zip(column_counts.iter()) {
                    for j in 0..*column_count {
                        start_indices_vec.push(((dense_size + j * row_count) >> 1) as u32);
                        col_index_vec
                            .extend_from_slice(&vec![(columns_so_far + j) as u32; *row_count >> 1]);
                    }
                    dense_size += row_count * column_count;

                    let row_indices = (0..*row_count).collect::<Vec<_>>();
                    for _ in 0..*column_count {
                        row.extend_from_slice(&row_indices);
                    }
                    columns_so_far += column_count;
                }
                start_indices_vec.push((dense_size >> 1) as u32);

                let dense_number_of_variables = dense_size.next_power_of_two().ilog2();
                tracing::info!("total number of variables: {}", dense_number_of_variables);

                // Create random base data and keep a CPU copy.
                let base_host = Tensor::<Felt>::rand(&mut rng, [dense_size]);
                let base_host_vec: Vec<Felt> = base_host.as_buffer().as_slice().to_vec();

                // Move base data to device.
                let base_device_buf = DeviceBuffer::from_host(base_host.as_buffer(), &t).unwrap();

                let dense_data = TraceDenseData {
                    dense: base_device_buf.into_inner(),
                    preprocessed_offset: 0,
                    preprocessed_cols: 0,
                    preprocessed_padding: 0,
                    main_padding: 0,
                    preprocessed_table_index: BTreeMap::new(),
                    main_table_index: BTreeMap::new(),
                };

                let col_index_buf = col_index_vec.clone().into_iter().collect();
                let col_index_device = DeviceBuffer::from_host(&col_index_buf, &t).unwrap();
                let start_indices_buf = start_indices_vec.into_iter().collect();
                let start_indices_device = DeviceBuffer::from_host(&start_indices_buf, &t).unwrap();

                let traces = JaggedTraceMle::new(
                    dense_data,
                    col_index_device.into_inner(),
                    start_indices_device.into_inner(),
                    Vec::new(),
                );

                // Compute expected claim on CPU:
                // \sum_i{base[i] * eq_row(z_row, row[i]) * eq_col(z_col, col[i])}
                let claim = (0..dense_size)
                    .into_par_iter()
                    .map(|i| {
                        let base_val = Ext::from_base(base_host_vec[i]);
                        let row_val = eq_z_row_vec[row[i]];
                        let col_val = eq_z_col_vec[col_index_vec[i >> 1] as usize];
                        base_val * (row_val * col_val)
                    })
                    .sum::<Ext>();

                // Run jagged sumcheck on GPU.
                let eq_z_col: Mle<Ext, TaskScope> = eq_z_col_device.into();
                let eq_z_row: Mle<Ext, TaskScope> = eq_z_row_device.into();

                let jagged_first_round_poly =
                    JaggedFirstRoundPoly::new(&traces, eq_z_col, eq_z_row, dense_size >> 1);

                let mut proof_challenger = challenger.clone();
                t.synchronize_blocking().unwrap();

                let now = std::time::Instant::now();
                let (proof, evaluations) =
                    jagged_sumcheck(jagged_first_round_poly, &mut proof_challenger, claim);
                t.synchronize_blocking().unwrap();
                tracing::info!("jagged sumcheck time: {:?}", now.elapsed());

                drop(traces);
                t.synchronize_blocking().unwrap();

                // Verify the sumcheck proof.
                let mut verification_challenger = challenger.clone();

                partially_verify_sumcheck_proof(
                    &proof,
                    &mut verification_challenger,
                    dense_number_of_variables as usize,
                    2,
                )
                .unwrap();

                tracing::info!("verifications passed");

                let (point, expected_final_eval) = proof.point_and_eval;

                assert_eq!(point.dimension() as u32, dense_number_of_variables);

                let [p_eval, q_eval]: [Ext; 2] = evaluations.try_into().unwrap();
                let final_eval = p_eval * q_eval;

                // q_eval should equal Mle(eq_row * eq_col) evaluated at the point.
                let jagged_poly = (0..dense_size)
                    .into_par_iter()
                    .map(|i| {
                        let row_val = eq_z_row_vec[row[i]];
                        let col_val = eq_z_col_vec[col_index_vec[i >> 1] as usize];
                        row_val * col_val
                    })
                    .collect::<Vec<_>>();
                let jagged_poly_mle = Mle::<Ext>::from(jagged_poly);
                let jagged_poly_device = DeviceMle::from_host(&jagged_poly_mle, &t).unwrap();

                let point_device = DevicePoint::from_host(&point, &t).unwrap();
                let jagged_eval = jagged_poly_device.eval_at_point(&point_device);
                let jagged_eval = jagged_eval.to_host_vec().unwrap()[0];
                assert_eq!(jagged_eval, q_eval, "jagged eval mismatch");

                drop(jagged_poly_device);
                t.synchronize_blocking().unwrap();

                // p_eval should equal Mle(base) evaluated at the point.
                let base_mle = Mle::<Felt>::from(base_host_vec);
                let base_device = DeviceMle::from_host(&base_mle, &t).unwrap();
                let base_eval = base_device.eval_at_point(&point_device);
                let base_eval = base_eval.to_host_vec().unwrap()[0];
                assert_eq!(base_eval, p_eval, "base eval mismatch");

                assert_eq!(final_eval, expected_final_eval, "final eval mismatch");

                tracing::info!("test case {} passed", i);
            }
        })
        .unwrap();
    }
}
