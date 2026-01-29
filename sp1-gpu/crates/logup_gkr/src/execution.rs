use slop_alloc::{Buffer, HasBackend};
use sp1_gpu_cudart::{
    args,
    sys::v2_kernels::{
        logup_gkr_circuit_transition, logup_gkr_extract_output, logup_gkr_first_layer_transition,
    },
    DeviceBuffer, DeviceMle,
};

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

    let (output_interaction_start_indices, output_interaction_row_counts) =
        layer.jagged_mle.next_start_indices_and_column_heights();

    let output_height = output_interaction_start_indices.last().copied().unwrap() as usize;
    let output_interaction_start_indices =
        DeviceBuffer::from_host(&output_interaction_start_indices, backend).unwrap().into_inner();

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
    let (output_interaction_start_indices, output_interaction_row_counts) =
        layer.jagged_mle.next_start_indices_and_column_heights();
    let output_height = output_interaction_start_indices.last().copied().unwrap() as usize;
    let output_interaction_start_indices =
        DeviceBuffer::from_host(&output_interaction_start_indices, backend).unwrap().into_inner();

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
/// doing all of the row variables.
pub fn extract_outputs(
    layer: &GkrLayer,
    num_interaction_variables: u32,
) -> DeviceLogUpGkrOutput<Ext> {
    let output_height = 1 << (num_interaction_variables + 1);
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
            grid_height
        );
        backend.launch_kernel(logup_gkr_extract_output(), grid_size, block_dim, &args, 0).unwrap();
    }

    DeviceLogUpGkrOutput { numerator, denominator }
}
