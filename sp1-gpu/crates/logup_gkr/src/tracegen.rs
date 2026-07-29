use std::{
    collections::{BTreeMap, BTreeSet},
    iter::once,
    sync::Arc,
};

use slop_alloc::{Buffer, HasBackend};
use slop_multilinear::Point;
use slop_tensor::Tensor;
use sp1_gpu_cudart::{
    args,
    sys::kernels::{logup_gkr_populate_last_circuit_layer, logup_gkr_populate_padding_columns},
    DeviceBuffer, DevicePoint, TaskScope,
};
use sp1_hypercube::{air::MachineAir, Chip};
use tracing::instrument;

use crate::{
    execution::DeviceLogUpGkrOutput,
    extract_outputs, gkr_transition,
    interactions::Interactions,
    layer::JaggedFirstGkrLayer,
    utils::{FirstGkrLayer, GkrCircuitLayer, GkrInputData, LogUpCudaCircuit},
};
use sp1_gpu_utils::{traces::JaggedTraceMle, JaggedMle};
use sp1_gpu_utils::{Ext, Felt};

pub struct CudaLogUpGkrOptions {
    pub recompute_first_layer: bool,
    pub num_row_variables: u32,
}

/// Generates the first layer of the GKR circuit.
///
/// Processes all of the chip interaction information and traces into GKR circuit format.
#[instrument(skip_all, level = "debug")]
pub fn generate_first_layer<'a>(
    input_data: &GkrInputData<'a>,
    backend: &TaskScope,
) -> FirstGkrLayer {
    let num_row_variables = input_data.num_row_variables - 1;

    // The shard's chips with interactions, in name order, each with its per-interaction column
    // height.
    let chip_interactions = input_data
        .all_interactions
        .iter()
        .filter(|(name, interactions)| {
            input_data.chip_set.contains(*name) && interactions.num_interactions > 0
        })
        .map(|(name, interactions)| {
            let real_height = input_data.poly_height(name).unwrap();
            // For padding reasons, `height` always needs to be at least 2.
            let height = std::cmp::max(real_height, 8);
            // Divide by 2 because each row has even height, so we only store length / 2.
            // Divide by 2 again because numerator(x, 0) and numerator(x, 1) are stored separately.
            let height = height.div_ceil(4) as u32;
            (name, interactions, height)
        })
        .collect::<Vec<_>>();

    // The grouped interaction-dimension shape, mirroring the native verifier's derivation: the
    // local-scope interactions form the low block `[0, num_local)`, the slots
    // `[num_local, 2^k_local)` are padding, and the global-scope interactions form the block
    // starting at `2^k_local` (above the local tree's padding slots), followed by padding up to
    // `2^k_full`. Columns are numbered by grouped index. The gap columns are materialized as
    // height-2 `(0, 1)` padding columns (like a fully-padded chip's), keeping dense position
    // equal to grouped index — the last-layer conversion to a dense interactions layer indexes
    // `eqInteraction` positionally. The tail beyond the last column flows through the
    // pre-existing eq-correction padding accounting.
    let num_local = chip_interactions
        .iter()
        .map(|(_, interactions, _)| interactions.num_local_interactions)
        .sum::<usize>();
    let num_global = chip_interactions
        .iter()
        .map(|(_, interactions, _)| {
            interactions.num_interactions - interactions.num_local_interactions
        })
        .sum::<usize>();
    let k_local = num_local.next_power_of_two().ilog2().max(1) as usize;
    let k_full = if num_global > 0 {
        ((1usize << k_local) + num_global).next_power_of_two().ilog2() as usize
    } else {
        k_local
    };
    let global_block_start = 1usize << k_local;
    let num_columns = global_block_start + num_global;

    // interaction_row_counts[g] is the column height of grouped interaction `g`; each chip's
    // grouped column offsets are its contiguous slices of the local and global blocks.
    let mut interaction_row_counts = vec![0u32; num_columns];
    let mut local_offset = 0usize;
    let mut global_offset = 0usize;
    let chip_offsets = chip_interactions
        .iter()
        .map(|(_, interactions, height)| {
            let chip_num_local = interactions.num_local_interactions;
            let chip_num_global = interactions.num_interactions - chip_num_local;
            let local_col_offset = local_offset;
            let global_col_offset = global_block_start + global_offset;
            interaction_row_counts[local_col_offset..local_col_offset + chip_num_local]
                .fill(*height);
            interaction_row_counts[global_col_offset..global_col_offset + chip_num_global]
                .fill(*height);
            local_offset += chip_num_local;
            global_offset += chip_num_global;
            (local_col_offset, global_col_offset)
        })
        .collect::<Vec<_>>();
    interaction_row_counts[num_local..global_block_start].fill(2);

    // interaction_start_indices is a prefix sum of interaction_row_counts.
    let interaction_start_indices = once(0)
        .chain(interaction_row_counts.iter().scan(0u32, |acc, x| {
            *acc += x;
            Some(*acc)
        }))
        .collect::<Buffer<_>>();
    let height = interaction_start_indices.last().copied().unwrap() as usize;

    let interaction_start_indices =
        DeviceBuffer::from_host(&interaction_start_indices, backend).unwrap().into_inner();
    let mut interaction_data = Buffer::<u32, _>::with_capacity_in(height, backend.clone());
    let mut numerator = Tensor::<Felt, _>::with_sizes_in([2, 1, height * 2], backend.clone());
    let mut denominator = Tensor::<Ext, _>::with_sizes_in([2, 1, height * 2], backend.clone());

    let beta = input_data.beta_seed.clone();
    let beta = DevicePoint::from_host(&beta, backend).unwrap().into_inner();
    let betas = DevicePoint::new(beta).partial_lagrange();

    let global_beta = input_data.global_beta_seed.clone();
    let global_beta = DevicePoint::from_host(&global_beta, backend).unwrap().into_inner();
    let global_betas = DevicePoint::new(global_beta).partial_lagrange();

    // Generate traces per chip, sorted by chip name.
    for ((name, interactions, _), (local_col_offset, global_col_offset)) in
        chip_interactions.iter().zip(chip_offsets)
    {
        let alpha = input_data.alpha;
        let global_alpha = input_data.global_alpha;
        let interactions = (*interactions).clone();
        let num_interactions = interactions.num_interactions;
        let interaction_start_indices = unsafe { interaction_start_indices.owned_unchecked() };
        let mut interaction_data = unsafe { interaction_data.owned_unchecked() };
        let mut numerator = unsafe { numerator.owned_unchecked() };
        let mut denominator = unsafe { denominator.owned_unchecked() };
        let real_height = input_data.poly_height(name).unwrap();

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
        let grid_size = (
            half_height.div_ceil(BLOCK_SIZE * ROW_STRIDE),
            num_interactions.div_ceil(INTERACTION_STRIDE),
            1,
        );
        unsafe {
            let preprocessed_ptr = input_data.preprocessed_ptr(name);
            let global_ptr = input_data.global_ptr(name);
            let main_ptr = input_data.main_ptr(name);

            let args = args!(
                interactions.as_raw(),
                interaction_start_indices.as_ptr(),
                interaction_data.as_mut_ptr(),
                numerator.as_mut_ptr(),
                denominator.as_mut_ptr(),
                preprocessed_ptr,
                global_ptr,
                main_ptr,
                alpha,
                betas.guts().as_ptr(),
                global_alpha,
                global_betas.guts().as_ptr(),
                local_col_offset,
                global_col_offset,
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

    // Materialize the local tree's padding columns (the gap `[num_local, 2^k_local)`) as `(0, 1)`
    // padding data, identical to a fully-padded chip's columns.
    let num_gap_columns = global_block_start - num_local;
    if num_gap_columns > 0 {
        const BLOCK_SIZE: usize = 256;
        let grid_size = (num_gap_columns.div_ceil(BLOCK_SIZE), 1, 1);
        unsafe {
            let args = args!(
                interaction_start_indices.as_ptr(),
                interaction_data.as_mut_ptr(),
                numerator.as_mut_ptr(),
                denominator.as_mut_ptr(),
                num_local,
                num_gap_columns,
                height
            );
            backend
                .launch_kernel(
                    logup_gkr_populate_padding_columns(),
                    grid_size,
                    BLOCK_SIZE,
                    &args,
                    0,
                )
                .unwrap();
        }
    }

    unsafe {
        interaction_data.assume_init();
        numerator.assume_init();
        denominator.assume_init();
    }

    // Height is half of the actual height of the numerator tensor.
    let height = numerator.sizes()[2] / 2;
    let jagged_layer = JaggedFirstGkrLayer { numerator, denominator, height };

    let interaction_row_counts_dev =
        DeviceBuffer::from_host_slice(&interaction_row_counts, backend).unwrap().into_inner();
    let jagged_mle = JaggedMle::new(
        jagged_layer,
        interaction_data,
        interaction_start_indices,
        interaction_row_counts_dev,
    );

    let num_interaction_variables = k_full as u32;

    FirstGkrLayer { jagged_mle, num_row_variables, num_interaction_variables }
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
                let layer = generate_first_layer(&self.input_data, self.backend());
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
    local_challenges: (Ext, Point<Ext>),
    global_challenges: (Ext, Point<Ext>),
    options: CudaLogUpGkrOptions,
    backend: TaskScope,
) -> (DeviceLogUpGkrOutput<Ext>, LogUpCudaCircuit<'a, TaskScope>) {
    let CudaLogUpGkrOptions { recompute_first_layer, num_row_variables } = options;
    let (alpha, beta_seed) = local_challenges;
    let (global_alpha, global_beta_seed) = global_challenges;
    let input_data = GkrInputData {
        chip_set: chips.iter().map(|chip| chip.name().to_string()).collect(),
        all_interactions,
        jagged_trace_data,
        alpha,
        beta_seed,
        global_alpha,
        global_beta_seed,
        num_row_variables,
        backend: backend.clone(),
    };

    let mut materialized_layers = Vec::new();

    // Generate the first layer.
    let first_layer = generate_first_layer(&input_data, &backend);
    let num_row_variables = first_layer.num_row_variables;
    let num_interaction_variables = first_layer.num_interaction_variables;

    let first_layer = GkrCircuitLayer::FirstLayer(first_layer);
    let layer = gkr_transition(&first_layer);

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
