use std::marker::PhantomData;

use slop_algebra::{ExtensionField, Field};
use slop_alloc::{Backend, Buffer, HasBackend};
use slop_jagged::deinterleave_prefix_sums;
use slop_multilinear::Point;
use slop_tensor::Tensor;
use sp1_gpu_cudart::reduce::DeviceSumKernel;
use sp1_gpu_cudart::transpose::DeviceTransposeKernel;
use sp1_gpu_cudart::{args, DeviceBuffer, DeviceTensor, TaskScope};

use crate::AsMutRawChallenger;
use crate::BranchingProgramKernel;

pub struct JaggedAssistSumAsPolyGPUImpl<F: Field, EF: ExtensionField<F>, Challenger> {
    z_row: Point<EF, TaskScope>,
    z_index: Point<EF, TaskScope>,
    current_prefix_sums: Tensor<F, TaskScope>,
    next_prefix_sums: Tensor<F, TaskScope>,
    prefix_sum_length: usize,
    num_columns: usize,
    num_layers: usize,
    half: EF,
    prefix_states: Buffer<EF, TaskScope>,
    suffix_vector_device: Buffer<EF, TaskScope>,
    round_claim_device: Buffer<EF, TaskScope>,
    _marker: PhantomData<Challenger>,
}

impl<F: Field, EF: ExtensionField<F>, Challenger> JaggedAssistSumAsPolyGPUImpl<F, EF, Challenger>
where
    TaskScope: Backend
        + DeviceSumKernel<EF>
        + DeviceTransposeKernel<F>
        + BranchingProgramKernel<F, EF, Challenger>,
{
    /// Returns `(Self, expected_sum)` where `expected_sum` is the full jagged little polynomial
    /// evaluation, computed as the dot product of `z_col_eq_vals` with the branching program
    /// evaluations extracted from `prefix_states[layer=0, state=INITIAL]`.
    pub fn new(
        z_row: Point<EF>,
        z_index: Point<EF>,
        merged_prefix_sums: &[Point<F>],
        z_col_eq_vals: &[EF],
        t: &TaskScope,
    ) -> (Self, EF) {
        // Convert z_row and z_index to device
        let z_row_buffer: Buffer<EF> = z_row.to_vec().into();
        let z_row_device: Point<EF, TaskScope> =
            Point::new(DeviceBuffer::from_host(&z_row_buffer, t).unwrap().into_inner());

        let z_index_buffer: Buffer<EF> = z_index.to_vec().into();
        let z_index_device: Point<EF, TaskScope> =
            Point::new(DeviceBuffer::from_host(&z_index_buffer, t).unwrap().into_inner());

        // De-interleave the merged prefix sums into separate current and next prefix sums.
        // Interleaved layout: [next[MSB], curr[MSB], next[MSB-1], curr[MSB-1], ..., next[LSB], curr[LSB]]
        let mut flattened_current_prefix_sums = Vec::new();
        let mut flattened_next_prefix_sums = Vec::new();
        for prefix_sum in merged_prefix_sums.iter() {
            let (current, next) = deinterleave_prefix_sums(prefix_sum);
            flattened_current_prefix_sums.extend(current.to_vec());
            flattened_next_prefix_sums.extend(next.to_vec());
        }

        let mut curr_prefix_sum_tensor: Tensor<F> = flattened_current_prefix_sums.into();
        let mut next_prefix_sum_tensor: Tensor<F> = flattened_next_prefix_sums.into();

        let num_columns = merged_prefix_sums.len();
        let prefix_sum_length = merged_prefix_sums[0].dimension() / 2;
        curr_prefix_sum_tensor.reshape_in_place([num_columns, prefix_sum_length]);
        next_prefix_sum_tensor.reshape_in_place([num_columns, prefix_sum_length]);

        // Use DeviceTensor's transpose method
        let curr_prefix_sums_device = DeviceTensor::from_host(&curr_prefix_sum_tensor, t).unwrap();
        let next_prefix_sums_device = DeviceTensor::from_host(&next_prefix_sum_tensor, t).unwrap();

        let curr_prefix_sums_device = curr_prefix_sums_device.transpose().into_inner();
        let next_prefix_sums_device = next_prefix_sums_device.transpose().into_inner();

        let half = EF::two().inverse();

        // Compute num_layers = 2 * (max(z_row_len, z_index_len) + 1)
        let num_layers =
            2 * (std::cmp::max(z_row_device.dimension(), z_index_device.dimension()) + 1);

        // Precompute prefix states on GPU
        let prefix_states_len = (num_layers + 1) * 8 * num_columns;
        let mut prefix_states = Buffer::with_capacity_in(prefix_states_len, t.clone());

        const BLOCK_SIZE: usize = 256;
        let grid_size_x = num_columns.div_ceil(BLOCK_SIZE);

        unsafe {
            prefix_states.set_len(prefix_states_len);
            let precompute_args = args!(
                curr_prefix_sums_device.as_ptr(),
                next_prefix_sums_device.as_ptr(),
                prefix_sum_length,
                z_row_device.as_ptr(),
                z_row_device.dimension(),
                z_index_device.as_ptr(),
                z_index_device.dimension(),
                num_columns,
                prefix_states.as_mut_ptr()
            );

            t.launch_kernel(
                <TaskScope as BranchingProgramKernel<F, EF, Challenger>>::precompute_prefix_states_kernel(),
                (grid_size_x, 1, 1),
                (BLOCK_SIZE, 1, 1),
                &precompute_args,
                0,
            )
            .unwrap();
        }

        // Compute expected sum from prefix_states at layer=0, state=INITIAL_STATE=0.
        // Layout: prefix_states[(layer * 8 + state) * num_columns + col], so layer=0, state=0
        // gives prefix_states[0..num_columns], which are the full BP evaluations per column.
        let mut bp_evals = Buffer::with_capacity_in(num_columns, t.clone());
        bp_evals.extend_from_device_slice(&prefix_states[..num_columns]).unwrap();
        let bp_evals_host = unsafe { bp_evals.copy_into_host_vec() };
        let expected_sum: EF =
            bp_evals_host.iter().zip(z_col_eq_vals.iter()).map(|(bp, zcol)| *bp * *zcol).sum();

        // Initialize round claim on device with expected_sum (avoids DtoH in sumcheck loop)
        let claim_buffer = Buffer::<EF>::from(vec![expected_sum]);
        let round_claim_device = DeviceBuffer::from_host(&claim_buffer, t).unwrap().into_inner();

        // Initialize suffix vector: [1, 0, 0, 0, 0, 0, 0, 0] (initial state at index 0)
        let mut suffix_init = vec![EF::zero(); 8];
        suffix_init[0] = EF::one();
        let suffix_buffer = Buffer::<EF>::from(suffix_init);
        let suffix_vector_device = DeviceBuffer::from_host(&suffix_buffer, t).unwrap().into_inner();

        (
            Self {
                z_row: z_row_device,
                z_index: z_index_device,
                current_prefix_sums: curr_prefix_sums_device,
                next_prefix_sums: next_prefix_sums_device,
                prefix_sum_length,
                num_columns,
                num_layers,
                half,
                prefix_states,
                suffix_vector_device,
                round_claim_device,
                _marker: PhantomData,
            },
            expected_sum,
        )
    }

    pub fn sum_as_poly_and_sample_into_point<OnDeviceChallenger: AsMutRawChallenger>(
        &mut self,
        round_num: usize,
        z_col_eq_vals: &Buffer<EF, TaskScope>,
        intermediate_eq_full_evals: &Buffer<EF, TaskScope>,
        sum_values: &mut Buffer<EF, TaskScope>,
        challenger: &mut OnDeviceChallenger,
        rhos: Point<EF, TaskScope>,
    ) -> Point<EF, TaskScope>
    where
        TaskScope: BranchingProgramKernel<F, EF, OnDeviceChallenger>,
    {
        let backend = self.current_prefix_sums.backend();

        const BLOCK_SIZE: usize = 256;
        let grid_size_x = self.num_columns.div_ceil(BLOCK_SIZE);

        // 1. Launch evalWithCachedAtZeroAndHalf kernel → [2, num_columns] output
        let mut eval_results: Tensor<EF, TaskScope> =
            Tensor::zeros_in([2, self.num_columns], backend.clone());

        unsafe {
            let eval_args = args!(
                self.prefix_states.as_ptr(),
                self.suffix_vector_device.as_ptr(),
                self.z_row.as_ptr(),
                self.z_row.dimension(),
                self.z_index.as_ptr(),
                self.z_index.dimension(),
                self.current_prefix_sums.as_ptr(),
                self.next_prefix_sums.as_ptr(),
                self.prefix_sum_length,
                z_col_eq_vals.as_ptr(),
                intermediate_eq_full_evals.as_ptr(),
                self.num_columns,
                round_num,
                self.half,
                eval_results.as_mut_ptr()
            );

            eval_results.assume_init();

            backend
                .launch_kernel(
                    <TaskScope as BranchingProgramKernel<F, EF, OnDeviceChallenger>>::eval_with_cached_kernel(),
                    (grid_size_x, 1, 1),
                    (BLOCK_SIZE, 1, 1),
                    &eval_args,
                    0,
                )
                .unwrap();
        }

        // 2. Reduce across columns → 2 values [y_0, y_half]
        let results = DeviceTensor::from_raw(eval_results).sum_dim(1).into_inner();

        // 3. Launch interpolateAndObserve kernel (reads/writes round_claim on device)
        let mut sampled_value = Buffer::with_capacity_in(rhos.dimension() + 1, backend.clone());

        unsafe {
            sampled_value.assume_init();
            let interp_args = args!(
                results.as_ptr(),
                challenger.as_mut_raw(),
                sampled_value.as_mut_ptr(),
                i8::try_from(round_num).unwrap(),
                sum_values.as_mut_ptr(),
                self.round_claim_device.as_mut_ptr()
            );

            backend
                .launch_kernel(
                    <TaskScope as BranchingProgramKernel<F, EF, OnDeviceChallenger>>::interpolate_and_observe_kernel(),
                    (1usize, 1, 1),
                    (BLOCK_SIZE, 1, 1),
                    &interp_args,
                    0,
                )
                .unwrap();

            sampled_value.set_len(1);
        }

        // 4. Launch updateSuffixVector kernel (single thread, reads alpha from sampled_value)
        unsafe {
            let suffix_args = args!(
                self.suffix_vector_device.as_mut_ptr(),
                sampled_value.as_ptr(),
                self.z_row.as_ptr(),
                self.z_row.dimension(),
                self.z_index.as_ptr(),
                self.z_index.dimension(),
                self.current_prefix_sums.as_ptr(),
                self.next_prefix_sums.as_ptr(),
                self.prefix_sum_length,
                self.num_columns,
                round_num,
                self.num_layers
            );

            backend
                .launch_kernel(
                    <TaskScope as BranchingProgramKernel<F, EF, OnDeviceChallenger>>::update_suffix_vector_kernel(),
                    (1usize, 1, 1),
                    (1usize, 1, 1),
                    &suffix_args,
                    0,
                )
                .unwrap();
        }

        // Build new rho point: [alpha, ...existing rhos]
        sampled_value.extend_from_device_slice(&rhos).unwrap();

        Point::new(sampled_value)
    }

    pub fn fix_last_variable_kernel<OnDeviceChallenger>(
        merged_prefix_sums: &Buffer<F, TaskScope>,
        intermediate_eq_full_evals: &mut Buffer<EF, TaskScope>,
        rho: &Point<EF, TaskScope>,
        merged_prefix_sum_dim: usize,
        round_num: usize,
    ) where
        TaskScope: BranchingProgramKernel<F, EF, OnDeviceChallenger>,
    {
        let backend = intermediate_eq_full_evals.backend().clone();

        const BLOCK_SIZE: usize = 512;
        const STRIDE: usize = 1;
        let grid_size_x = merged_prefix_sums.len().div_ceil(BLOCK_SIZE * STRIDE);
        let grid_size = (grid_size_x, 1, 1);

        unsafe {
            let args = args!(
                merged_prefix_sums.as_ptr(),
                intermediate_eq_full_evals.as_mut_ptr(),
                rho.as_ptr(),
                merged_prefix_sum_dim,
                intermediate_eq_full_evals.len(),
                round_num,
                rho.dimension()
            );

            backend
                .launch_kernel(
                    <TaskScope as BranchingProgramKernel<F, EF, OnDeviceChallenger>>::fix_last_variable(),
                    grid_size,
                    (BLOCK_SIZE, 1, 1),
                    &args,
                    0,
                )
                .unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;
    use rand::Rng;
    use slop_algebra::extension::BinomialExtensionField;
    use slop_algebra::AbstractField;
    use slop_alloc::Buffer;
    use sp1_gpu_challenger::DuplexChallenger;
    use sp1_gpu_cudart::TaskScope;
    use sp1_primitives::SP1Field;

    type F = SP1Field;
    type EF = BinomialExtensionField<F, 4>;

    #[test]
    fn test_fix_last_variable() {
        let merged_prefix_sum_dim = 50;

        let num_columns = 1000;

        let mut rng = rand::thread_rng();

        let intermediate_eq_full_evals =
            (0..num_columns).map(|_| rng.gen::<EF>()).collect::<Vec<_>>();

        let merged_prefix_sums =
            (0..num_columns * merged_prefix_sum_dim).map(|_| rng.gen::<F>()).collect::<Vec<_>>();

        let new_randomness_point =
            (0..merged_prefix_sum_dim).map(|_| rng.gen::<EF>()).collect::<Vec<_>>();

        sp1_gpu_cudart::run_sync_in_place(|backend| {
            for round_num in 0..merged_prefix_sum_dim {
                let merged_prefix_sums_buffer = Buffer::<F>::from(merged_prefix_sums.clone());
                let merged_prefix_sums_device =
                    DeviceBuffer::from_host(&merged_prefix_sums_buffer, &backend)
                        .unwrap()
                        .into_inner();

                let intermediate_eq_full_evals_buffer =
                    Buffer::<EF>::from(intermediate_eq_full_evals.clone());
                let mut intermediate_eq_full_evals_device =
                    DeviceBuffer::from_host(&intermediate_eq_full_evals_buffer, &backend)
                        .unwrap()
                        .into_inner();

                let new_randomness_point_buffer = Buffer::<EF>::from(new_randomness_point.clone());
                let new_randomness_point_device =
                    DeviceBuffer::from_host(&new_randomness_point_buffer, &backend)
                        .unwrap()
                        .into_inner();

                const BLOCK_SIZE: usize = 512;
                const STRIDE: usize = 1;
                let grid_size_x = merged_prefix_sums_device.len().div_ceil(BLOCK_SIZE * STRIDE);
                let grid_size = (grid_size_x, 1, 1);

                unsafe {
                    let time = std::time::Instant::now();
                    let args = args!(
                        merged_prefix_sums_device.as_ptr(),
                        intermediate_eq_full_evals_device.as_mut_ptr(),
                        new_randomness_point_device.as_ptr(),
                        { merged_prefix_sum_dim },
                        { num_columns },
                        { round_num },
                        new_randomness_point_device.len()
                    );

                    backend
                        .launch_kernel(
                            <TaskScope as BranchingProgramKernel<
                                F,
                                EF,
                                DuplexChallenger<F, TaskScope>,
                            >>::fix_last_variable(),
                            grid_size,
                            (BLOCK_SIZE, 1, 1),
                            &args,
                            0,
                        )
                        .unwrap();
                    tracing::info!("Kernel execution time: {:?}", time.elapsed());
                }
                let intermediate_eq_full_evals_from_device =
                    DeviceBuffer::from_raw(intermediate_eq_full_evals_device).to_host().unwrap();

                let alpha = *new_randomness_point.first().unwrap();

                let expected_intermediate_eq_full_evals = merged_prefix_sums
                    .to_vec()
                    .chunks(merged_prefix_sum_dim)
                    .zip_eq(intermediate_eq_full_evals.iter())
                    .map(|(merged_prefix_sum, intermediate_eq_full_eval)| {
                        let x_i =
                            merged_prefix_sum.get(merged_prefix_sum_dim - 1 - round_num).unwrap();
                        *intermediate_eq_full_eval
                            * ((alpha * *x_i) + (EF::one() - alpha) * (EF::one() - *x_i))
                    })
                    .collect_vec();

                for (i, (expected, actual)) in expected_intermediate_eq_full_evals
                    .iter()
                    .zip_eq(intermediate_eq_full_evals_from_device.iter())
                    .enumerate()
                {
                    assert_eq!(expected, actual, "Mismatch at index {i}");
                }
            }
        })
        .unwrap();
    }
}
