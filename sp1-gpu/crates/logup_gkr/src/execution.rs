use slop_alloc::{Buffer, HasBackend};
use slop_multilinear::Mle;
use sp1_gpu_cudart::{
    args,
    sys::kernels::{
        logup_gkr_build_interaction_layer, logup_gkr_circuit_transition, logup_gkr_extract_output,
        logup_gkr_first_layer_transition,
    },
    DeviceBuffer, DeviceMle, TaskScope,
};
use sp1_hypercube::{GlobalInteractionOutput, LogUpGkrOutput};

use slop_tensor::Tensor;

use crate::layer::JaggedGkrLayer;
use crate::utils::{FirstGkrLayer, GkrCircuitLayer, GkrLayer};
use sp1_gpu_utils::{Ext, JaggedMle};

/// Takes as input a GkrLayer, which represents evaluations of p_0, p_1, q_0, q_1.
/// Computes the next layer like
/// p_0_next[i] = p_0[i] * q_1[i] + p_1[i] * q_0[i]
/// p_1_next[i] = p_0[i + 1] * q_1[i + 1] + p_1[i + 1] * q_0[i + 1]
/// q_0_next[i] = q_1[i] * q_0[i]
/// q_1_next[i] = q_1[i + 1] * q_0[i + 1]
///
/// Since each layer needs to have a multiple-of-four size, sometimes we need to add padding
/// values to the last row. In practice, since every row is even, we just add 2 padding
/// values to rows with length 2 mod 4.
pub fn layer_transition(layer: &GkrLayer) -> GkrLayer {
    let backend = layer.jagged_mle.backend();
    let height = layer.jagged_mle.dense_data.height;

    let (output_interaction_start_indices, output_interaction_row_counts, output_height_u32) =
        layer.jagged_mle.next_start_indices_and_column_heights_dev();
    let output_height = output_height_u32 as usize;

    // Create a new layer
    let output_layer: Tensor<Ext, _> =
        Tensor::with_sizes_in([4, 1, output_height * 2], backend.clone());

    let output_col_index: Buffer<u32, _> = Buffer::with_capacity_in(output_height, backend.clone());

    // populate the new layer
    const BLOCK_SIZE: usize = 256;
    const STRIDE: usize = 32;
    let grid_size_x = height.div_ceil(BLOCK_SIZE * STRIDE);
    let grid_size = (grid_size_x, 1, 1);
    let block_dim = BLOCK_SIZE;

    let device_output_gkr_layer = JaggedGkrLayer::new(output_layer, output_height);
    let mut output_jagged_mle = JaggedMle::new(
        device_output_gkr_layer,
        output_col_index,
        output_interaction_start_indices,
        output_interaction_row_counts,
    );

    unsafe {
        output_jagged_mle.dense_data.assume_init();
        output_jagged_mle.col_index.assume_init();
        let args = args!(layer.jagged_mle.as_raw(), output_jagged_mle.as_mut_raw());
        backend
            .launch_kernel(logup_gkr_circuit_transition(), grid_size, block_dim, &args, 0)
            .unwrap();
    }

    GkrLayer {
        jagged_mle: output_jagged_mle,
        num_row_variables: layer.num_row_variables - 1,
        num_interaction_variables: layer.num_interaction_variables,
    }
}

/// Combines numerator and denominator polynomials into the next gkr layer.
pub fn first_layer_transition(layer: &FirstGkrLayer) -> GkrLayer {
    let backend = layer.jagged_mle.backend();
    let height = layer.jagged_mle.dense_data.height;

    // If this is not the last layer, we need to fix the last variable and create a
    // new circuit layer.
    let (output_interaction_start_indices, output_interaction_row_counts, output_height_u32) =
        layer.jagged_mle.next_start_indices_and_column_heights_dev();
    let output_height = output_height_u32 as usize;

    // Create a new layer
    let output_layer: Tensor<Ext, _> =
        Tensor::with_sizes_in([4, 1, output_height * 2], backend.clone());
    let output_col_index: Buffer<u32, _> = Buffer::with_capacity_in(output_height, backend.clone());

    let output_gkr_layer = JaggedGkrLayer::new(output_layer, output_height);
    let mut output_jagged_mle = JaggedMle::new(
        output_gkr_layer,
        output_col_index,
        output_interaction_start_indices,
        output_interaction_row_counts,
    );

    // populate the new layer
    const BLOCK_SIZE: usize = 256;
    const STRIDE: usize = 32;
    let grid_size_x = height.div_ceil(BLOCK_SIZE * STRIDE);
    let grid_size = (grid_size_x, 1, 1);
    let block_dim = BLOCK_SIZE;
    unsafe {
        output_jagged_mle.dense_data.assume_init();
        output_jagged_mle.col_index.assume_init();

        let args = args!(layer.jagged_mle.as_raw(), output_jagged_mle.as_mut_raw());
        backend
            .launch_kernel(logup_gkr_first_layer_transition(), grid_size, block_dim, &args, 0)
            .unwrap();
    }
    GkrLayer {
        jagged_mle: output_jagged_mle,
        num_row_variables: layer.num_row_variables - 1,
        num_interaction_variables: layer.num_interaction_variables,
    }
}

/// Wrapper for layer_transition and first_layer_transition. Do this for every row_variable.
pub fn gkr_transition<'a>(layer: &GkrCircuitLayer<'a>) -> GkrCircuitLayer<'a> {
    match layer {
        GkrCircuitLayer::FirstLayer(layer) => {
            GkrCircuitLayer::Materialized(first_layer_transition(layer))
        }
        GkrCircuitLayer::Materialized(layer) => {
            GkrCircuitLayer::Materialized(layer_transition(layer))
        }
        GkrCircuitLayer::FirstLayerVirtual(_) => {
            unreachable!()
        }
    }
}

pub struct DeviceLogUpGkrOutput<Ext> {
    pub numerator: DeviceMle<Ext>,
    pub denominator: DeviceMle<Ext>,
}

/// Takes as input the input layer p_0, p_1, q_0, q_1, after finishing the circuit section and
/// doing all of the row variables. Produces the base of `2^(num_interaction_variables + 1)`
/// fractions in grouped interaction order: slots `(2g, 2g + 1)` hold grouped interaction `g`'s
/// two last-row-variable halves, and every uncovered slot (the gap below `2^k_local` and the
/// tail) holds the `(0, 1)` padding values.
pub fn extract_outputs(
    layer: &GkrLayer,
    num_interaction_variables: u32,
) -> DeviceLogUpGkrOutput<Ext> {
    let output_height = 1 << (num_interaction_variables + 1);
    let num_columns = layer.jagged_mle.column_heights().len();
    let backend = layer.jagged_mle.backend();

    let mut numerator = DeviceMle::uninit(1, output_height, backend);
    let mut denominator = DeviceMle::uninit(1, output_height, backend);

    const BLOCK_SIZE: usize = 256;
    const STRIDE: usize = 4;
    let grid_height = output_height.div_ceil(2);
    let grid_size_x = grid_height.div_ceil(BLOCK_SIZE * STRIDE);
    let grid_size = (grid_size_x, 1, 1);
    let block_dim = BLOCK_SIZE;

    unsafe {
        numerator.assume_init();
        denominator.assume_init();
        let args = args!(
            layer.jagged_mle.as_raw(),
            numerator.guts_mut().as_mut_ptr(),
            denominator.guts_mut().as_mut_ptr(),
            num_columns,
            grid_height
        );
        backend.launch_kernel(logup_gkr_extract_output(), grid_size, block_dim, &args, 0).unwrap();
    }

    DeviceLogUpGkrOutput { numerator, denominator }
}

/// The device interaction-combining layers together with the host-side values extracted from the
/// combination: the 2-entry circuit output and the exposed global-interaction outputs.
pub struct InteractionLayers {
    /// One dense `[4, half]` interaction layer (`n0 || n1 || d0 || d1`) per combine step, in
    /// build order: `il_0` (over the full `2^(k_full + 1)` base) first, then the local-tree
    /// levels, finest children first. The rounds are proved back-to-front.
    pub layers: Vec<Tensor<Ext, TaskScope>>,
    /// The 2-entry circuit output (the top of the proved local tree).
    pub output: LogUpGkrOutput<Ext>,
    /// The exposed global-scope interaction outputs `o_full[2^k_local + i]`, `i < num_global`,
    /// in grouped (block) order.
    pub global_interaction_outputs: Vec<GlobalInteractionOutput<Ext>>,
}

/// Copy `len` elements of a single-polynomial device MLE starting at `start` to the host.
fn copy_range_to_host(mle: &DeviceMle<Ext>, start: usize, len: usize) -> Vec<Ext> {
    let mut staging = DeviceBuffer::<Ext>::with_capacity_in(len, mle.backend().clone());
    staging.extend_from_device_slice(&mle.guts().view().as_buffer()[start..start + len]).unwrap();
    staging.to_host().unwrap()
}

/// Combine one interaction-dimension level: fold the interleaved pairs `(2j, 2j + 1)` of the
/// leading `2 * half` entries of `numerator`/`denominator` into their `half` fraction sums,
/// materializing the child pairs into a dense `[4, half]` interaction layer.
fn combine_interaction_level(
    numerator: &DeviceMle<Ext>,
    denominator: &DeviceMle<Ext>,
    half: usize,
) -> (Tensor<Ext, TaskScope>, DeviceMle<Ext>, DeviceMle<Ext>) {
    let backend = numerator.backend().clone();

    let mut layer = Tensor::<Ext, _>::with_sizes_in([4, half], backend.clone());
    let mut next_numerator = DeviceMle::uninit(1, half, &backend);
    let mut next_denominator = DeviceMle::uninit(1, half, &backend);

    const BLOCK_SIZE: usize = 256;
    let grid_size = (half.div_ceil(BLOCK_SIZE), 1, 1);

    unsafe {
        layer.assume_init();
        next_numerator.assume_init();
        next_denominator.assume_init();
        let args = args!(
            numerator.guts().as_ptr(),
            denominator.guts().as_ptr(),
            layer.as_mut_ptr(),
            next_numerator.guts_mut().as_mut_ptr(),
            next_denominator.guts_mut().as_mut_ptr(),
            half
        );
        backend
            .launch_kernel(logup_gkr_build_interaction_layer(), grid_size, BLOCK_SIZE, &args, 0)
            .unwrap();
    }

    (layer, next_numerator, next_denominator)
}

/// Tree-combines the interaction dimension of the `2^(k_full + 1)` grouped base on the device:
/// one combine step over the full base gives the "one entry per interaction" layer `o_full`
/// (whose gap and tail are exactly `(0, 1)`); the exposed global-interaction outputs are
/// suffix-copied to the host from `o_full`'s global block; and the local tree then combines the
/// `2^k_local` prefix of `o_full` down to the 2-entry circuit output. Without a global round,
/// `k_full == k_local` and the prefix is the whole of `o_full`.
pub fn build_interaction_layers(
    base: DeviceLogUpGkrOutput<Ext>,
    k_full: usize,
    k_local: usize,
    num_global: usize,
) -> InteractionLayers {
    let DeviceLogUpGkrOutput { numerator, denominator } = base;

    // `il_0`: combine the interleaved base pairs into `o_full`.
    let (il_0, o_full_numerator, o_full_denominator) =
        combine_interaction_level(&numerator, &denominator, 1 << k_full);

    // Suffix-copy only the `2 * num_global` exposed elements of `o_full`'s global block, which
    // starts at `2^k_local`.
    let global_block_start = 1usize << k_local;
    let global_interaction_outputs = if num_global == 0 {
        Vec::new()
    } else {
        let global_numerators =
            copy_range_to_host(&o_full_numerator, global_block_start, num_global);
        let global_denominators =
            copy_range_to_host(&o_full_denominator, global_block_start, num_global);
        global_numerators.into_iter().zip(global_denominators).collect()
    };

    // The local tree: `k_local - 1` combine steps over the `2^k_local` prefix (whose gap already
    // carries the `(0, 1)` padding). The first step reads only the prefix of the oversized
    // `o_full`; every later level is exact-sized.
    let mut layers = Vec::with_capacity(k_local);
    layers.push(il_0);
    let mut cur_numerator = o_full_numerator;
    let mut cur_denominator = o_full_denominator;
    let mut len = 1usize << k_local;
    while len > 2 {
        let half = len / 2;
        let (layer, next_numerator, next_denominator) =
            combine_interaction_level(&cur_numerator, &cur_denominator, half);
        layers.push(layer);
        cur_numerator = next_numerator;
        cur_denominator = next_denominator;
        len = half;
    }

    // The circuit output is the leading pair of the final level (all of it after at least one
    // combine step; the 2-entry prefix of `o_full` when `k_local == 1`).
    let output = LogUpGkrOutput {
        numerator: Mle::from(copy_range_to_host(&cur_numerator, 0, 2)),
        denominator: Mle::from(copy_range_to_host(&cur_denominator, 0, 2)),
    };

    InteractionLayers { layers, output, global_interaction_outputs }
}
