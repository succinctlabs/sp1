use std::marker::PhantomData;

use slop_algebra::{ExtensionField, Field};
use slop_alloc::{Backend, Buffer, HasBackend};
use slop_multilinear::Point;
use sp1_gpu_cudart::reduce::DeviceSumKernel;
use sp1_gpu_cudart::{args, DeviceBuffer, TaskScope};

use crate::AsMutRawChallenger;
use crate::BranchingProgramKernel;

pub struct JaggedAssistSumAsPolyGPUImpl<F: Field, EF: ExtensionField<F>, Challenger> {
    z_row: Point<EF, TaskScope>,
    z_index: Point<EF, TaskScope>,
    /// Packed per-column prefix sums: bit `i` of `current_prefix_sums[col]` is the i-th LSB.
    current_prefix_sums: Buffer<u32, TaskScope>,
    next_prefix_sums: Buffer<u32, TaskScope>,
    prefix_sum_length: usize,
    num_columns: usize,
    half: EF,
    prefix_states: Buffer<EF, TaskScope>,
    suffix_vector_device: Buffer<EF, TaskScope>,
    round_claim_device: Buffer<EF, TaskScope>,
    _marker: PhantomData<(F, Challenger)>,
}

impl<F: Field, EF: ExtensionField<F>, Challenger> JaggedAssistSumAsPolyGPUImpl<F, EF, Challenger>
where
    TaskScope: Backend + DeviceSumKernel<EF> + BranchingProgramKernel<F, EF, Challenger>,
{
    /// Build the GPU state from condensed `(curr, next)` prefix-sum pairs.
    ///
    /// The curr/next prefix sums are uploaded as one `u32` per column with the
    /// raw bit pattern; the kernel reads bit `i` via
    /// `getIthBitFromPackedColumn`, materializing `F::zero()`/`F::one()` on
    /// the fly without any base-field promotion on the host.
    pub fn new(
        z_row: Point<EF>,
        z_index: Point<EF>,
        prefix_sum_pairs: &[(usize, usize)],
        prefix_sum_length: usize,
        expected_sum: EF,
        t: &TaskScope,
    ) -> Self {
        // Kernel reads `(packed >> i) & 1` for `i < prefix_sum_length`; u32 is enough
        // for any realistic shard layout.
        assert!(prefix_sum_length <= 32, "prefix_sum_length {prefix_sum_length} exceeds u32 width");

        let z_row_buffer: Buffer<EF> = z_row.to_vec().into();
        let z_row_device: Point<EF, TaskScope> =
            Point::new(DeviceBuffer::from_host(&z_row_buffer, t).unwrap().into_inner());

        let z_index_buffer: Buffer<EF> = z_index.to_vec().into();
        let z_index_device: Point<EF, TaskScope> =
            Point::new(DeviceBuffer::from_host(&z_index_buffer, t).unwrap().into_inner());

        let num_columns = prefix_sum_pairs.len();

        // One pass over `prefix_sum_pairs`: just truncate each prefix-sum
        // index to u32. No bit extraction, no field promotion, no transpose.
        let current_packed: Vec<u32> = prefix_sum_pairs.iter().map(|&(c, _)| c as u32).collect();
        let next_packed: Vec<u32> = prefix_sum_pairs.iter().map(|&(_, n)| n as u32).collect();

        let current_prefix_sums =
            DeviceBuffer::from_host(&Buffer::from(current_packed), t).unwrap().into_inner();
        let next_prefix_sums =
            DeviceBuffer::from_host(&Buffer::from(next_packed), t).unwrap().into_inner();

        let half = EF::two().inverse();

        // num_layers = 2 * (max(z_row_len, z_index_len) + 1)
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
                current_prefix_sums.as_ptr(),
                next_prefix_sums.as_ptr(),
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

        // Initialize round claim on device with expected_sum (avoids DtoH in sumcheck loop)
        let claim_buffer = Buffer::<EF>::from(vec![expected_sum]);
        let round_claim_device = DeviceBuffer::from_host(&claim_buffer, t).unwrap().into_inner();

        // Initialize suffix vector: [1, 0, 0, 0, 0, 0, 0, 0] (initial state at index 0)
        let mut suffix_init = vec![EF::zero(); 8];
        suffix_init[0] = EF::one();
        let suffix_buffer = Buffer::<EF>::from(suffix_init);
        let suffix_vector_device = DeviceBuffer::from_host(&suffix_buffer, t).unwrap().into_inner();

        Self {
            z_row: z_row_device,
            z_index: z_index_device,
            current_prefix_sums,
            next_prefix_sums,
            prefix_sum_length,
            num_columns,
            half,
            prefix_states,
            suffix_vector_device,
            round_claim_device,
            _marker: PhantomData,
        }
    }

    /// Run all sumcheck rounds in a single cooperative kernel launch.
    /// Returns `(sum_values, rho_buffer)` where:
    /// - `sum_values[3*round + {0,1,2}]` contains (y0, yhalf, y1) for each round
    /// - `rho_buffer[round]` contains alpha for each round (forward order)
    pub fn fused_sumcheck<OnDeviceChallenger: AsMutRawChallenger>(
        &mut self,
        num_rounds: usize,
        z_col_eq_vals: &Buffer<EF, TaskScope>,
        intermediate_eq_full_evals: &mut Buffer<EF, TaskScope>,
        sum_values: &mut Buffer<EF, TaskScope>,
        challenger: &mut OnDeviceChallenger,
    ) -> Buffer<EF, TaskScope>
    where
        TaskScope: BranchingProgramKernel<F, EF, OnDeviceChallenger>,
    {
        let backend = self.current_prefix_sums.backend();

        const BLOCK_SIZE: i32 = 256;
        let shared_mem = (8 + BLOCK_SIZE as usize) * std::mem::size_of::<EF>();

        // Query max cooperative grid size (consumes kernel ptr, so get it again for launch)
        let occupancy_kernel =
            <TaskScope as BranchingProgramKernel<F, EF, OnDeviceChallenger>>::fused_sumcheck_kernel(
            );
        let max_blocks =
            TaskScope::max_cooperative_blocks(occupancy_kernel, BLOCK_SIZE, shared_mem).unwrap();
        let needed_blocks = self.num_columns.div_ceil(BLOCK_SIZE as usize);
        let grid_size = std::cmp::min(needed_blocks, max_blocks as usize);

        // Allocate workspace
        let mut block_partial_sums: Buffer<EF, TaskScope> =
            Buffer::with_capacity_in(2 * grid_size, backend.clone());
        unsafe { block_partial_sums.set_len(2 * grid_size) };

        let mut rho_buffer = Buffer::with_capacity_in(num_rounds, backend.clone());
        unsafe { rho_buffer.set_len(num_rounds) };

        let kernel =
            <TaskScope as BranchingProgramKernel<F, EF, OnDeviceChallenger>>::fused_sumcheck_kernel(
            );

        unsafe {
            let kernel_args = args!(
                self.prefix_states.as_ptr(),
                self.z_row.as_ptr(),
                self.z_row.dimension(),
                self.z_index.as_ptr(),
                self.z_index.dimension(),
                self.current_prefix_sums.as_ptr(),
                self.next_prefix_sums.as_ptr(),
                self.prefix_sum_length,
                z_col_eq_vals.as_ptr(),
                self.half,
                self.num_columns,
                num_rounds,
                self.suffix_vector_device.as_mut_ptr(),
                self.round_claim_device.as_mut_ptr(),
                intermediate_eq_full_evals.as_mut_ptr(),
                challenger.as_mut_raw(),
                sum_values.as_mut_ptr(),
                rho_buffer.as_mut_ptr(),
                block_partial_sums.as_mut_ptr()
            );

            backend
                .launch_cooperative_kernel(
                    kernel,
                    grid_size,
                    BLOCK_SIZE as usize,
                    &kernel_args,
                    shared_mem,
                )
                .unwrap();
        }

        rho_buffer
    }
}
