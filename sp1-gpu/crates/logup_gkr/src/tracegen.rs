use std::{
    collections::{BTreeMap, BTreeSet},
    iter::once,
    sync::Arc,
};

use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use slop_alloc::{Buffer, HasBackend};
use slop_multilinear::Point;
use slop_tensor::Tensor;
use sp1_gpu_cudart::{
    args,
    sys::v2_kernels::{
        logup_gkr_populate_first_and_second_circuit_layer, logup_gkr_populate_last_circuit_layer,
    },
    DeviceBuffer, DevicePoint, TaskScope,
};
use sp1_hypercube::{air::MachineAir, Chip};
use tracing::instrument;

use crate::{
    execution::DeviceLogUpGkrOutput,
    extract_outputs, gkr_transition,
    interactions::Interactions,
    layer::{JaggedFirstGkrLayer, JaggedGkrLayer},
    utils::{FirstGkrLayer, GkrCircuitLayer, GkrInputData, GkrLayer, LogUpCudaCircuit},
};
use sp1_gpu_utils::{traces::JaggedTraceMle, JaggedMle};
use sp1_gpu_utils::{Ext, Felt};

/// The maximum number of GKR transitions that can be fused into the first-layer kernel.
///
/// Currently only `K = 1` is implemented; `K = 2` would require warp-shuffle plumbing on the
/// `Felt` / `Ext` field types and `K = 3` is unsolved.
pub const MAX_FUSED_TRANSITIONS: u32 = 1;

pub struct CudaLogUpGkrOptions {
    pub recompute_first_layer: bool,
    pub num_row_variables: u32,
    /// Number of GKR transitions to fuse into the first-layer kernel (0 = unchanged behaviour, 1 =
    /// produce layer 2 in the same launch). Capped at [`MAX_FUSED_TRANSITIONS`].
    pub num_fused_transitions: u32,
}

/// Generates the first layer of the GKR circuit.
///
/// Processes all of the chip interaction information and traces into GKR circuit format. When
/// `num_fused_transitions == 1`, the first GKR transition is also produced in the same kernel
/// launch and returned as the second element of the tuple. The caller is responsible for stitching
/// these into the materialized-layer chain.
///
/// `num_fused_transitions` must be in `0..=MAX_FUSED_TRANSITIONS`. The fused path requires every
/// per-interaction layer-1 row count to be a multiple of 2 (in row units), which is the case for
/// all real-world chips here (column heights are multiples of 32).
#[instrument(skip_all, level = "debug")]
pub fn generate_first_layer<'a>(
    input_data: &GkrInputData<'a>,
    backend: &TaskScope,
    num_fused_transitions: u32,
) -> (FirstGkrLayer, Vec<GkrLayer>) {
    assert!(
        num_fused_transitions <= MAX_FUSED_TRANSITIONS,
        "num_fused_transitions must be in 0..={MAX_FUSED_TRANSITIONS}"
    );
    let num_row_variables = input_data.num_row_variables - 1;

    // Layer-1 per-interaction row counts (column heights, in row units).
    let interaction_row_counts =
        tracing::trace_span!("row counts and start indices").in_scope(|| {
            input_data
                .all_interactions
                .par_iter()
                .filter(|(name, _)| input_data.chip_set.contains(*name))
                .flat_map(|(name, interactions)| {
                    let real_height = input_data.main_poly_height(name).unwrap();
                    // For padding reasons, `height` always needs to be at least 2.
                    let height = std::cmp::max(real_height, 8);
                    // Divide by 2 because each row has even height, so we only store length / 2.
                    // Divide by 2 again because numerator(x, 0) and numerator(x, 1) are stored separately.
                    let height = height.div_ceil(4);
                    vec![height as u32; interactions.num_interactions]
                })
                .collect::<Vec<_>>()
        });

    // Layer-1 start indices: prefix sum of layer-1 row counts.
    let interaction_start_indices_host = once(0)
        .chain(interaction_row_counts.iter().scan(0u32, |acc, x| {
            *acc += x;
            Some(*acc)
        }))
        .collect::<Buffer<_>>();
    let height = interaction_start_indices_host.last().copied().unwrap() as usize;

    // Layer-2 metadata if we're fusing. Mirrors `next_start_indices_and_column_heights`:
    // `output_heights[col] = column_heights[col].div_ceil(4) * 2`.
    let fuse = num_fused_transitions == 1;
    let (layer2_row_counts, layer2_start_indices_host, layer2_height) = if fuse {
        let l2_row_counts: Vec<u32> =
            interaction_row_counts.iter().map(|h| h.div_ceil(4) * 2).collect();
        let l2_start_indices: Buffer<u32> = once(0)
            .chain(l2_row_counts.iter().scan(0u32, |acc, x| {
                *acc += x;
                Some(*acc)
            }))
            .collect::<Buffer<_>>();
        let l2_height = l2_start_indices.last().copied().unwrap() as usize;
        (l2_row_counts, Some(l2_start_indices), l2_height)
    } else {
        (Vec::new(), None, 0)
    };

    let interaction_start_indices =
        DeviceBuffer::from_host(&interaction_start_indices_host, backend).unwrap().into_inner();
    let mut interaction_data = Buffer::<u32, _>::with_capacity_in(height, backend.clone());
    let mut numerator = Tensor::<Felt, _>::with_sizes_in([2, 1, height * 2], backend.clone());
    let mut denominator = Tensor::<Ext, _>::with_sizes_in([2, 1, height * 2], backend.clone());

    // Layer-2 buffers (only when fusing).
    let (layer2_start_indices, mut layer2_col_index, mut layer2_layer) = if fuse {
        let l2_start_indices_host = layer2_start_indices_host.as_ref().unwrap();
        let l2_start_indices =
            DeviceBuffer::from_host(l2_start_indices_host, backend).unwrap().into_inner();
        let l2_col_index = Buffer::<u32, _>::with_capacity_in(layer2_height, backend.clone());
        let l2_layer = Tensor::<Ext, _>::with_sizes_in([4, 1, layer2_height * 2], backend.clone());
        (Some(l2_start_indices), Some(l2_col_index), Some(l2_layer))
    } else {
        (None, None, None)
    };

    let beta = input_data.beta_seed.clone();
    let beta = DevicePoint::from_host(&beta, backend).unwrap().into_inner();
    let betas = DevicePoint::new(beta).partial_lagrange();

    // Generate traces per chip, sorted by chip name.
    let mut interaction_offset = 0;
    for (name, interactions) in
        input_data.all_interactions.iter().filter(|(name, _)| input_data.chip_set.contains(*name))
    {
        let alpha = input_data.alpha;
        let interactions = interactions.clone();
        let num_interactions = interactions.num_interactions;
        let interaction_start_indices = unsafe { interaction_start_indices.owned_unchecked() };
        let mut interaction_data = unsafe { interaction_data.owned_unchecked() };
        let mut numerator = unsafe { numerator.owned_unchecked() };
        let mut denominator = unsafe { denominator.owned_unchecked() };
        let real_height = input_data.main_poly_height(name).unwrap();

        const BLOCK_SIZE: usize = 256;
        const ROW_STRIDE: usize = 8;
        const INTERACTION_STRIDE: usize = 4;
        // To fit the padding requirement, each trace must have even height.
        assert_eq!(real_height % 2, 0);
        let is_padding = real_height == 0;

        // half_height is max(1, ceil(real_height / 2))
        let matrix_height = std::cmp::max(real_height, 2);
        let half_height = matrix_height.div_ceil(2);

        let block_dim = BLOCK_SIZE;
        unsafe {
            let preprocessed_ptr = input_data.preprocessed_ptr(name);
            let main_ptr = input_data.main_ptr(name);

            if fuse {
                // Each thread handles one layer-1 row pair (= one layer-2 stored element).
                // pair_count = half_height / 2 layer-2 stored elements per column.
                const FUSED_ROW_STRIDE: usize = 4;
                let pair_count = half_height / 2;
                let grid_size = (
                    pair_count.div_ceil(BLOCK_SIZE * FUSED_ROW_STRIDE).max(1),
                    num_interactions.div_ceil(INTERACTION_STRIDE),
                    1,
                );

                let layer2_start_indices = layer2_start_indices.as_ref().unwrap().owned_unchecked();
                let mut layer2_col_index = layer2_col_index.as_mut().unwrap().owned_unchecked();
                let mut layer2_layer = layer2_layer.as_mut().unwrap().owned_unchecked();

                let args = args!(
                    interactions.as_raw(),
                    interaction_start_indices.as_ptr(),
                    interaction_data.as_mut_ptr(),
                    numerator.as_mut_ptr(),
                    denominator.as_mut_ptr(),
                    layer2_start_indices.as_ptr(),
                    layer2_col_index.as_mut_ptr(),
                    layer2_layer.as_mut_ptr(),
                    preprocessed_ptr,
                    main_ptr,
                    alpha,
                    betas.guts().as_ptr(),
                    interaction_offset,
                    real_height,
                    height,
                    layer2_height,
                    is_padding
                );
                backend
                    .launch_kernel(
                        logup_gkr_populate_first_and_second_circuit_layer(),
                        grid_size,
                        block_dim,
                        &args,
                        0,
                    )
                    .unwrap();
            } else {
                let grid_size = (
                    half_height.div_ceil(BLOCK_SIZE * ROW_STRIDE),
                    num_interactions.div_ceil(INTERACTION_STRIDE),
                    1,
                );
                let args = args!(
                    interactions.as_raw(),
                    interaction_start_indices.as_ptr(),
                    interaction_data.as_mut_ptr(),
                    numerator.as_mut_ptr(),
                    denominator.as_mut_ptr(),
                    preprocessed_ptr,
                    main_ptr,
                    alpha,
                    betas.guts().as_ptr(),
                    interaction_offset,
                    real_height,
                    height,
                    is_padding
                );
                backend
                    .launch_kernel(
                        logup_gkr_populate_last_circuit_layer(),
                        grid_size,
                        block_dim,
                        &args,
                        0,
                    )
                    .unwrap();
            }
        }

        interaction_offset += num_interactions;
    }

    unsafe {
        interaction_data.assume_init();
        numerator.assume_init();
        denominator.assume_init();
        if let Some(c) = layer2_col_index.as_mut() {
            c.assume_init();
        }
        if let Some(l) = layer2_layer.as_mut() {
            l.assume_init();
        }
    }

    // Height is half of the actual height of the numerator tensor.
    let layer1_height = numerator.sizes()[2] / 2;
    let jagged_layer = JaggedFirstGkrLayer { numerator, denominator, height: layer1_height };

    let jagged_mle = JaggedMle::new(
        jagged_layer,
        interaction_data,
        interaction_start_indices,
        interaction_row_counts,
    );

    let num_interaction_variables = interaction_offset.next_power_of_two().ilog2();

    let first_layer = FirstGkrLayer { jagged_mle, num_row_variables, num_interaction_variables };

    let fused_layers = if fuse {
        let layer2_jagged = JaggedGkrLayer::new(layer2_layer.unwrap(), layer2_height);
        let layer2_mle = JaggedMle::new(
            layer2_jagged,
            layer2_col_index.unwrap(),
            layer2_start_indices.unwrap(),
            layer2_row_counts,
        );
        vec![GkrLayer {
            jagged_mle: layer2_mle,
            num_row_variables: num_row_variables - 1,
            num_interaction_variables,
        }]
    } else {
        Vec::new()
    };

    (first_layer, fused_layers)
}

impl<'a> LogUpCudaCircuit<'a, TaskScope> {
    pub fn next(&'_ mut self, recompute_first_layer: bool) -> Option<GkrCircuitLayer<'_>> {
        if recompute_first_layer {
            if let Some(layer) = self.materialized_layers.pop() {
                Some(layer)
            } else {
                if self.num_virtual_layers == 0 {
                    return None;
                }
                assert!(self.num_virtual_layers == 1);
                // We need to generate the virtual layers and store them in the circuit.
                // Recompute path always reproduces the first layer alone; fused transitions are
                // not regenerated here.
                let (layer, _fused) = generate_first_layer(&self.input_data, self.backend(), 0);
                self.num_virtual_layers = 0;
                Some(GkrCircuitLayer::FirstLayer(layer))
            }
        } else {
            self.materialized_layers.pop()
        }
    }
}

/// Generates a GKR circuit from the given chips and jagged trace data.
#[instrument(skip_all, level = "debug")]
pub fn generate_gkr_circuit<'a, A: MachineAir<Felt>>(
    chips: &BTreeSet<Chip<Felt, A>>,
    all_interactions: BTreeMap<String, Arc<Interactions<Felt, TaskScope>>>,
    jagged_trace_data: &'a JaggedTraceMle<Felt, TaskScope>,
    alpha: Ext,
    beta_seed: Point<Ext>,
    options: CudaLogUpGkrOptions,
    backend: TaskScope,
) -> (DeviceLogUpGkrOutput<Ext>, LogUpCudaCircuit<'a, TaskScope>) {
    let CudaLogUpGkrOptions { recompute_first_layer, num_row_variables, num_fused_transitions } =
        options;
    assert!(
        num_fused_transitions <= MAX_FUSED_TRANSITIONS,
        "num_fused_transitions must be in 0..={MAX_FUSED_TRANSITIONS}"
    );
    let input_data = GkrInputData {
        chip_set: chips.iter().map(|chip| chip.name().to_string()).collect(),
        all_interactions,
        jagged_trace_data,
        alpha,
        beta_seed,
        num_row_variables,
        backend: backend.clone(),
    };

    let mut materialized_layers = Vec::new();

    // Generate the first layer (and optionally the first transition fused into the same kernel).
    let (first_layer, fused_layers) =
        generate_first_layer(&input_data, &backend, num_fused_transitions);
    let num_row_variables = first_layer.num_row_variables;
    let num_interaction_variables = first_layer.num_interaction_variables;

    let first_layer = GkrCircuitLayer::FirstLayer(first_layer);
    // Layer 2: either fused (already produced) or computed via the standard transition.
    let layer = if let Some(fused_l2) = fused_layers.into_iter().next() {
        GkrCircuitLayer::Materialized(fused_l2)
    } else {
        gkr_transition(&first_layer)
    };

    if recompute_first_layer {
        drop(first_layer);
    } else {
        materialized_layers.push(first_layer);
    }

    // Transition from the previous layer to generate the next one.
    materialized_layers.push(layer);
    for i in 0..num_row_variables - 2 {
        let layer = tracing::trace_span!("gkr transition", layer = i)
            .in_scope(|| gkr_transition(materialized_layers.last().unwrap()));
        materialized_layers.push(layer);
    }

    let last_layer =
        if let GkrCircuitLayer::Materialized(last_layer) = materialized_layers.last().unwrap() {
            last_layer
        } else {
            panic!("last layer not correct");
        };
    assert_eq!(last_layer.num_row_variables, 1);

    // Extract the outputs from the last layer.
    let output = extract_outputs(last_layer, num_interaction_variables);
    let circuit = LogUpCudaCircuit { materialized_layers, input_data, num_virtual_layers: 1 };

    (output, circuit)
}
