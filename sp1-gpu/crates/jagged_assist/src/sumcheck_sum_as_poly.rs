use std::marker::PhantomData;

use slop_algebra::{AbstractField, Field};
use slop_alloc::{Backend, Buffer, HasBackend};
use slop_multilinear::Point;
use sp1_gpu_cudart::reduce::DeviceSumKernel;
use sp1_gpu_cudart::{args, DeviceBuffer, TaskScope};
use sp1_gpu_utils::{Ext, Felt};

use crate::AsMutRawChallenger;
use crate::BranchingProgramKernel;

pub struct JaggedAssistSumAsPolyGPUImpl<Challenger> {
    z_row: Point<Ext, TaskScope>,
    z_index: Point<Ext, TaskScope>,
    /// Packed per-column prefix sums: bit `i` of `current_prefix_sums[col]` is the i-th LSB.
    current_prefix_sums: Buffer<u32, TaskScope>,
    next_prefix_sums: Buffer<u32, TaskScope>,
    prefix_sum_length: usize,
    num_columns: usize,
    half: Ext,
    prefix_states: Buffer<Ext, TaskScope>,
    /// Width-4 prefix states for the geq BP (`next >= curr`). Layout matches
    /// the assist's prefix_states but with `GEQ_BP_WIDTH = 4` per (layer, col).
    geq_prefix_states: Buffer<Ext, TaskScope>,
    suffix_vector_device: Buffer<Ext, TaskScope>,
    /// Width-4 suffix vector for the geq BP, initialized at the prover's
    /// initial state `(cso=1, saved=0) = index 2`.
    geq_suffix_vector_device: Buffer<Ext, TaskScope>,
    round_claim_device: Buffer<Ext, TaskScope>,
    _marker: PhantomData<Challenger>,
}

impl<Challenger> JaggedAssistSumAsPolyGPUImpl<Challenger>
where
    TaskScope: Backend + DeviceSumKernel<Ext> + BranchingProgramKernel<Felt, Ext, Challenger>,
{
    /// Build the GPU state from condensed `(curr, next)` prefix-sum pairs.
    ///
    /// The curr/next prefix sums are uploaded as one `u32` per column with the
    /// raw bit pattern; the kernel reads bit `i` via
    /// `getIthBitFromPackedColumn`, materializing `F::zero()`/`F::one()` on
    /// the fly without any base-field promotion on the host.
    pub fn new(
        z_row: Point<Ext>,
        z_index: Point<Ext>,
        prefix_sum_pairs: &[(usize, usize)],
        prefix_sum_length: usize,
        expected_sum: Ext,
        t: &TaskScope,
    ) -> Self {
        // Kernel reads `(packed >> i) & 1` for `i < prefix_sum_length`; u32 is enough
        // for any realistic shard layout.
        assert!(prefix_sum_length <= 32, "prefix_sum_length {prefix_sum_length} exceeds u32 width");

        let z_row_buffer: Buffer<Ext> = z_row.to_vec().into();
        let z_row_device: Point<Ext, TaskScope> =
            Point::new(DeviceBuffer::from_host(&z_row_buffer, t).unwrap().into_inner());

        let z_index_buffer: Buffer<Ext> = z_index.to_vec().into();
        let z_index_device: Point<Ext, TaskScope> =
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

        let half = Ext::two().inverse();

        // Assist BP layer count, distinct from the geq BP's: the assist BP's
        // `num_vars = max(z_row_len, z_index_len)` may exceed `prefix_sum_length`.
        let assist_num_layers =
            2 * (std::cmp::max(z_row_device.dimension(), z_index_device.dimension()) + 1);
        let geq_num_layers = 2 * prefix_sum_length;

        // Precompute prefix states on GPU for both BPs in one pass.
        let prefix_states_len = (assist_num_layers + 1) * 8 * num_columns;
        let geq_prefix_states_len = (geq_num_layers + 1) * 4 * num_columns;
        let mut prefix_states = Buffer::with_capacity_in(prefix_states_len, t.clone());
        let mut geq_prefix_states = Buffer::with_capacity_in(geq_prefix_states_len, t.clone());

        const BLOCK_SIZE: usize = 256;
        let grid_size_x = num_columns.div_ceil(BLOCK_SIZE);

        unsafe {
            prefix_states.set_len(prefix_states_len);
            geq_prefix_states.set_len(geq_prefix_states_len);
            let precompute_args = args!(
                current_prefix_sums.as_ptr(),
                next_prefix_sums.as_ptr(),
                prefix_sum_length,
                z_row_device.as_ptr(),
                z_row_device.dimension(),
                z_index_device.as_ptr(),
                z_index_device.dimension(),
                num_columns,
                prefix_states.as_mut_ptr(),
                geq_prefix_states.as_mut_ptr()
            );

            t.launch_kernel(
                <TaskScope as BranchingProgramKernel<Felt, Ext, Challenger>>::precompute_prefix_states_kernel(),
                (grid_size_x, 1, 1),
                (BLOCK_SIZE, 1, 1),
                &precompute_args,
                0,
            )
            .unwrap();
        }

        // Initialize round claim on device with expected_sum (avoids DtoH in sumcheck loop)
        let claim_buffer = Buffer::<Ext>::from(vec![expected_sum]);
        let round_claim_device = DeviceBuffer::from_host(&claim_buffer, t).unwrap().into_inner();

        // Initialize suffix vector: [1, 0, 0, 0, 0, 0, 0, 0] (initial state at index 0)
        let mut suffix_init = vec![Ext::zero(); 8];
        suffix_init[0] = Ext::one();
        let suffix_buffer = Buffer::<Ext>::from(suffix_init);
        let suffix_vector_device = DeviceBuffer::from_host(&suffix_buffer, t).unwrap().into_inner();

        // Geq suffix vector: initial state at `(cso=1, saved=0) = 2`.
        let mut geq_suffix_init = vec![Ext::zero(); 4];
        geq_suffix_init[2] = Ext::one();
        let geq_suffix_buffer = Buffer::<Ext>::from(geq_suffix_init);
        let geq_suffix_vector_device =
            DeviceBuffer::from_host(&geq_suffix_buffer, t).unwrap().into_inner();

        Self {
            z_row: z_row_device,
            z_index: z_index_device,
            current_prefix_sums,
            next_prefix_sums,
            prefix_sum_length,
            num_columns,
            half,
            prefix_states,
            geq_prefix_states,
            suffix_vector_device,
            geq_suffix_vector_device,
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
        z_col_eq_vals: &Buffer<Ext, TaskScope>,
        intermediate_eq_full_evals: &mut Buffer<Ext, TaskScope>,
        sum_values: &mut Buffer<Ext, TaskScope>,
        challenger: &mut OnDeviceChallenger,
        combine_alpha: Ext,
    ) -> Buffer<Ext, TaskScope>
    where
        TaskScope: BranchingProgramKernel<Felt, Ext, OnDeviceChallenger>,
    {
        let backend = self.current_prefix_sums.backend();

        const BLOCK_SIZE: i32 = 256;
        // Shared memory: 8 EF for assist suffix + 4 EF for geq suffix + BLOCK_SIZE EF
        // for the block-reduction scratch.
        let shared_mem = (8 + 4 + BLOCK_SIZE as usize) * std::mem::size_of::<Ext>();

        // Query max cooperative grid size (consumes kernel ptr, so get it again for launch)
        let occupancy_kernel = <TaskScope as BranchingProgramKernel<
            Felt,
            Ext,
            OnDeviceChallenger,
        >>::fused_sumcheck_kernel();
        let max_blocks =
            TaskScope::max_cooperative_blocks(occupancy_kernel, BLOCK_SIZE, shared_mem).unwrap();
        let needed_blocks = self.num_columns.div_ceil(BLOCK_SIZE as usize);
        let grid_size = std::cmp::min(needed_blocks, max_blocks as usize);

        // Allocate workspace
        let mut block_partial_sums: Buffer<Ext, TaskScope> =
            Buffer::with_capacity_in(2 * grid_size, backend.clone());
        unsafe { block_partial_sums.set_len(2 * grid_size) };

        let mut rho_buffer = Buffer::with_capacity_in(num_rounds, backend.clone());
        unsafe { rho_buffer.set_len(num_rounds) };

        let kernel =
            <TaskScope as BranchingProgramKernel<Felt, Ext, OnDeviceChallenger>>::fused_sumcheck_kernel(
            );

        unsafe {
            let kernel_args = args!(
                self.prefix_states.as_ptr(),
                self.geq_prefix_states.as_ptr(),
                self.z_row.as_ptr(),
                self.z_row.dimension(),
                self.z_index.as_ptr(),
                self.z_index.dimension(),
                self.current_prefix_sums.as_ptr(),
                self.next_prefix_sums.as_ptr(),
                self.prefix_sum_length,
                z_col_eq_vals.as_ptr(),
                self.half,
                combine_alpha,
                self.num_columns,
                num_rounds,
                self.suffix_vector_device.as_mut_ptr(),
                self.geq_suffix_vector_device.as_mut_ptr(),
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
