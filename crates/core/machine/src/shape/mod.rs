use std::collections::BTreeMap;
use std::str::FromStr;

use hashbrown::HashMap;
use itertools::Itertools;
use num::Integer;
use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;
use p3_util::log2_ceil_usize;
use sp1_core_executor::{ExecutionRecord, Program, RiscvAirId};
use sp1_stark::{
    air::MachineAir,
    shape::{OrderedShape, Shape, ShapeCluster},
    MachineRecord,
};
use thiserror::Error;

use super::riscv::riscv_chips::{ByteChip, ProgramChip, SyscallChip};
use crate::{
    global::GlobalChip,
    memory::{MemoryLocalChip, NUM_LOCAL_MEMORY_ENTRIES_PER_ROW},
    riscv::RiscvAir,
};

/// The set of maximal shapes.
///
/// These shapes define the "worst-case" shapes for typical shards that are proving `rv32im`
/// execution. We use a variant of a cartesian product of the allowed log heights to generate
/// smaller shapes from these ones.
const MAXIMAL_SHAPES: &[u8] = include_bytes!("maximal_shapes.json");

/// The set of tiny shapes.
///
/// These shapes are used to optimize performance for smaller programs.
const SMALL_SHAPES: &[u8] = include_bytes!("small_shapes.json");

/// A configuration for what shapes are allowed to be used by the prover.
#[derive(Debug)]
pub struct CoreShapeConfig<F: PrimeField32> {
    partial_preprocessed_shapes: ShapeCluster<RiscvAirId>,
    partial_core_shapes: BTreeMap<usize, Vec<ShapeCluster<RiscvAirId>>>,
    partial_memory_shapes: ShapeCluster<RiscvAirId>,
    partial_precompile_shapes: HashMap<RiscvAir<F>, (usize, Vec<usize>)>,
    partial_small_shapes: Vec<ShapeCluster<RiscvAirId>>,
    costs: HashMap<RiscvAirId, usize>,
}

impl<F: PrimeField32> CoreShapeConfig<F> {
    /// Fix the preprocessed shape of the proof.
    pub fn fix_preprocessed_shape(&self, program: &mut Program) -> Result<(), CoreShapeError> {
        // If the preprocessed shape is already fixed, return an error.
        if program.preprocessed_shape.is_some() {
            return Err(CoreShapeError::PreprocessedShapeAlreadyFixed);
        }

        // Get the heights of the preprocessed chips and find a shape that fits.
        let preprocessed_heights = RiscvAir::<F>::preprocessed_heights(program);
        let preprocessed_shape = self
            .partial_preprocessed_shapes
            .find_shape(&preprocessed_heights)
            .ok_or(CoreShapeError::PreprocessedShapeError)?;

        // Set the preprocessed shape.
        program.preprocessed_shape = Some(preprocessed_shape);

        Ok(())
    }

    /// Fix the shape of the proof.
    pub fn fix_shape(&self, record: &mut ExecutionRecord) -> Result<(), CoreShapeError> {
        if record.program.preprocessed_shape.is_none() {
            return Err(CoreShapeError::PrepcocessedShapeMissing);
        }
        if record.shape.is_some() {
            return Err(CoreShapeError::ShapeAlreadyFixed);
        }

        // Set the shape of the chips with prepcoded shapes to match the preprocessed shape from the
        // program.
        record.shape.clone_from(&record.program.preprocessed_shape);

        // If this is a packed "core" record where the cpu events are alongisde the memory init and
        // finalize events, try to fix the shape using the tiny shapes.
        if record.contains_cpu()
            && (!record.global_memory_finalize_events.is_empty()
                || !record.global_memory_initialize_events.is_empty())
        {
            // Get the heights of the core airs in the record.
            let mut heights = RiscvAir::<F>::core_heights(record);
            heights.extend(RiscvAir::<F>::memory_heights(record));

            // Try to find a shape fitting within at least one of the candidate shapes.
            let mut minimal_shape = None;
            let mut minimal_area = usize::MAX;
            let mut minimal_cluster = None;
            for (i, cluster) in self.partial_small_shapes.iter().enumerate() {
                if let Some(shape) = cluster.find_shape(&heights) {
                    if self.estimate_lde_size(&shape) < minimal_area {
                        minimal_area = self.estimate_lde_size(&shape);
                        minimal_shape = Some(shape);
                        minimal_cluster = Some(i);
                    }
                }
            }

            if let Some(shape) = minimal_shape {
                let shard = record.public_values.shard;
                tracing::info!(
                    "Shard Lifted: Index={}, Cluster={}",
                    shard,
                    minimal_cluster.unwrap()
                );
                for (air, height) in heights.iter() {
                    if shape.contains(air) {
                        tracing::info!(
                            "Chip {:<20}: {:<3} -> {:<3}",
                            air,
                            log2_ceil_usize(*height),
                            shape.log2_height(air).unwrap(),
                        );
                    }
                }
                record.shape.as_mut().unwrap().extend(shape);
                return Ok(());
            }

            // No shape found, so return an error.
            return Err(CoreShapeError::ShapeError(
                heights
                    .into_iter()
                    .map(|(air, height)| (air.to_string(), log2_ceil_usize(height)))
                    .collect(),
            ));
        }

        // If this is a normal "core" record, try to fix the shape as such.
        if record.contains_cpu() {
            // Get the heights of the core airs in the record.
            let heights = RiscvAir::<F>::core_heights(record);

            // Try to find the smallest shape fitting within at least one of the candidate shapes.
            let log2_shard_size = record.cpu_events.len().next_power_of_two().ilog2() as usize;
            let mut minimal_shape = None;
            let mut minimal_area = usize::MAX;
            let mut minimal_cluster = None;
            for (_, clusters) in self.partial_core_shapes.range(log2_shard_size..) {
                for (i, cluster) in clusters.iter().enumerate() {
                    if let Some(shape) = cluster.find_shape(&heights) {
                        if self.estimate_lde_size(&shape) < minimal_area {
                            minimal_area = self.estimate_lde_size(&shape);
                            minimal_shape = Some(shape.clone());
                            minimal_cluster = Some(i);
                        }
                    }
                }
            }

            if let Some(shape) = minimal_shape {
                let shard = record.public_values.shard;
                let cluster = minimal_cluster.unwrap();
                tracing::info!("Shard Lifted: Index={}, Cluster={}", shard, cluster);

                for (air, height) in heights.iter() {
                    if shape.contains(air) {
                        tracing::info!(
                            "Chip {:<20}: {:<3} -> {:<3}",
                            air,
                            log2_ceil_usize(*height),
                            shape.log2_height(air).unwrap(),
                        );
                    }
                }
                record.shape.as_mut().unwrap().extend(shape);
                return Ok(());
            }

            // No shape found, so return an error.
            return Err(CoreShapeError::ShapeError(record.stats()));
        }

        // If the record is a does not have the CPU chip and is a global memory init/finalize
        // record, try to fix the shape as such.
        if !record.global_memory_initialize_events.is_empty()
            || !record.global_memory_finalize_events.is_empty()
        {
            let heights = RiscvAir::<F>::memory_heights(record);
            let shape = self
                .partial_memory_shapes
                .find_shape(&heights)
                .ok_or(CoreShapeError::ShapeError(record.stats()))?;
            record.shape.as_mut().unwrap().extend(shape);
            return Ok(());
        }

        // Try to fix the shape as a precompile record.
        for (air, (memory_events_per_row, allowed_log2_heights)) in
            self.partial_precompile_shapes.iter()
        {
            if let Some((height, num_memory_local_events, num_global_events)) =
                air.precompile_heights(record)
            {
                for allowed_log2_height in allowed_log2_heights {
                    let allowed_height = 1 << allowed_log2_height;
                    if height <= allowed_height {
                        for shape in self.get_precompile_shapes(
                            air,
                            *memory_events_per_row,
                            *allowed_log2_height,
                        ) {
                            let mem_events_height = shape[2].1;
                            let global_events_height = shape[3].1;
                            if num_memory_local_events.div_ceil(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW)
                                <= (1 << mem_events_height)
                                && num_global_events <= (1 << global_events_height)
                            {
                                record.shape.as_mut().unwrap().extend(
                                    shape
                                        .iter()
                                        .map(|x| (RiscvAirId::from_str(&x.0).unwrap(), x.1)),
                                );
                                return Ok(());
                            }
                        }
                    }
                }
                tracing::error!(
                    "Cannot find shape for precompile {:?}, height {:?}, and mem events {:?}",
                    air.name(),
                    height,
                    num_memory_local_events
                );
                return Err(CoreShapeError::ShapeError(record.stats()));
            }
        }

        Err(CoreShapeError::PrecompileNotIncluded(record.stats()))
    }

    // TODO: this function is atrocious, fix this
    fn get_precompile_shapes(
        &self,
        air: &RiscvAir<F>,
        memory_events_per_row: usize,
        allowed_log2_height: usize,
    ) -> Vec<[(String, usize); 4]> {
        // TODO: This is a temporary fix to the shape, concretely fix this
        (1..=4 * air.rows_per_event())
            .rev()
            .map(|rows_per_event| {
                let num_local_mem_events =
                    ((1 << allowed_log2_height) * memory_events_per_row).div_ceil(rows_per_event);
                [
                    (air.name(), allowed_log2_height),
                    (
                        RiscvAir::<F>::SyscallPrecompile(SyscallChip::precompile()).name(),
                        ((1 << allowed_log2_height)
                            .div_ceil(&air.rows_per_event())
                            .next_power_of_two()
                            .ilog2() as usize)
                            .max(4),
                    ),
                    (
                        RiscvAir::<F>::MemoryLocal(MemoryLocalChip::new()).name(),
                        (num_local_mem_events
                            .div_ceil(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW)
                            .next_power_of_two()
                            .ilog2() as usize)
                            .max(4),
                    ),
                    (
                        RiscvAir::<F>::Global(GlobalChip).name(),
                        ((2 * num_local_mem_events
                            + (1 << allowed_log2_height).div_ceil(&air.rows_per_event()))
                        .next_power_of_two()
                        .ilog2() as usize)
                            .max(4),
                    ),
                ]
            })
            .filter(|shape| shape[3].1 <= 22)
            .collect::<Vec<_>>()
    }

    fn generate_all_shapes_from_allowed_log_heights(
        allowed_log_heights: impl IntoIterator<Item = (String, Vec<Option<usize>>)>,
    ) -> impl Iterator<Item = OrderedShape> {
        allowed_log_heights
            .into_iter()
            .map(|(name, heights)| heights.into_iter().map(move |height| (name.clone(), height)))
            .multi_cartesian_product()
            .map(|iter| {
                iter.into_iter()
                    .filter_map(|(name, maybe_height)| {
                        maybe_height.map(|log_height| (name, log_height))
                    })
                    .collect::<OrderedShape>()
            })
    }

    pub fn all_shapes(&self) -> impl Iterator<Item = OrderedShape> + '_ {
        let preprocessed_heights = self
            .partial_preprocessed_shapes
            .iter()
            .map(|(air, heights)| (air.to_string(), heights.clone()))
            .collect::<HashMap<_, _>>();

        let mut memory_heights = self
            .partial_memory_shapes
            .iter()
            .map(|(air, heights)| (air.to_string(), heights.clone()))
            .collect::<HashMap<_, _>>();
        memory_heights.extend(preprocessed_heights.clone());

        let precompile_only_shapes = self.partial_precompile_shapes.iter().flat_map(
            move |(air, (mem_events_per_row, allowed_log_heights))| {
                allowed_log_heights.iter().flat_map(move |allowed_log_height| {
                    self.get_precompile_shapes(air, *mem_events_per_row, *allowed_log_height)
                })
            },
        );

        let precompile_shapes =
            Self::generate_all_shapes_from_allowed_log_heights(preprocessed_heights.clone())
                .flat_map(move |preprocessed_shape| {
                    precompile_only_shapes.clone().map(move |precompile_shape| {
                        preprocessed_shape
                            .clone()
                            .into_iter()
                            .chain(precompile_shape)
                            .collect::<OrderedShape>()
                    })
                });

        self.partial_core_shapes
            .values()
            .flatten()
            .chain(self.partial_small_shapes.iter())
            .flat_map(move |allowed_log_heights| {
                Self::generate_all_shapes_from_allowed_log_heights({
                    let mut log_heights = allowed_log_heights
                        .iter()
                        .map(|(air, heights)| (air.to_string(), heights.clone()))
                        .collect::<HashMap<_, _>>();
                    log_heights.extend(preprocessed_heights.clone());
                    log_heights
                })
            })
            .chain(Self::generate_all_shapes_from_allowed_log_heights(memory_heights))
            .chain(precompile_shapes)
    }

    pub fn maximal_core_shapes(&self, max_log_shard_size: usize) -> Vec<Shape<RiscvAirId>> {
        let max_shard_size: usize = core::cmp::max(
            1 << max_log_shard_size,
            1 << self.partial_core_shapes.keys().min().unwrap(),
        );

        let log_shard_size = max_shard_size.ilog2() as usize;
        debug_assert_eq!(1 << log_shard_size, max_shard_size);
        let max_preprocessed = self
            .partial_preprocessed_shapes
            .iter()
            .map(|(air, allowed_heights)| {
                (air.to_string(), allowed_heights.last().unwrap().unwrap())
            })
            .collect::<HashMap<_, _>>();

        let max_core_shapes =
            self.partial_core_shapes[&log_shard_size].iter().map(|allowed_log_heights| {
                max_preprocessed
                    .clone()
                    .into_iter()
                    .chain(allowed_log_heights.iter().flat_map(|(air, allowed_heights)| {
                        allowed_heights
                            .last()
                            .unwrap()
                            .map(|log_height| (air.to_string(), log_height))
                    }))
                    .map(|(air, log_height)| (RiscvAirId::from_str(&air).unwrap(), log_height))
                    .collect::<Shape<RiscvAirId>>()
            });

        max_core_shapes.collect()
    }

    pub fn maximal_core_plus_precompile_shapes(
        &self,
        max_log_shard_size: usize,
    ) -> Vec<Shape<RiscvAirId>> {
        let max_preprocessed = self
            .partial_preprocessed_shapes
            .iter()
            .map(|(air, allowed_heights)| {
                (air.to_string(), allowed_heights.last().unwrap().unwrap())
            })
            .collect::<HashMap<_, _>>();

        let precompile_only_shapes = self.partial_precompile_shapes.iter().flat_map(
            move |(air, (mem_events_per_row, allowed_log_heights))| {
                self.get_precompile_shapes(
                    air,
                    *mem_events_per_row,
                    *allowed_log_heights.last().unwrap(),
                )
            },
        );

        let precompile_shapes: Vec<Shape<RiscvAirId>> = precompile_only_shapes
            .map(|x| {
                max_preprocessed
                    .clone()
                    .into_iter()
                    .chain(x)
                    .map(|(air, log_height)| (RiscvAirId::from_str(&air).unwrap(), log_height))
                    .collect::<Shape<RiscvAirId>>()
            })
            .filter(|shape| shape.log2_height(&RiscvAirId::Global).unwrap() < 21)
            .collect();

        self.maximal_core_shapes(max_log_shard_size).into_iter().chain(precompile_shapes).collect()
    }

    fn estimate_lde_size(&self, shape: &Shape<RiscvAirId>) -> usize {
        shape.iter().map(|(air, height)| self.costs[air] * (1 << height)).sum()
    }

    // TODO: cleanup..
    pub fn small_program_shapes(&self) -> Vec<OrderedShape> {
        self.partial_small_shapes
            .iter()
            .map(|log_heights| {
                OrderedShape::from_log2_heights(
                    &log_heights
                        .iter()
                        .filter(|(_, v)| v[0].is_some())
                        .map(|(k, v)| (k.to_string(), v.last().unwrap().unwrap()))
                        .chain(vec![
                            (MachineAir::<BabyBear>::name(&ProgramChip), 19),
                            (MachineAir::<BabyBear>::name(&ByteChip::default()), 16),
                        ])
                        .collect::<Vec<_>>(),
                )
            })
            .collect()
    }
}

impl<F: PrimeField32> Default for CoreShapeConfig<F> {
    fn default() -> Self {
        // Load the maximal shapes.
        let maximal_shapes: BTreeMap<usize, Vec<Shape<RiscvAirId>>> =
            serde_json::from_slice(MAXIMAL_SHAPES).unwrap();
        let small_shapes: Vec<Shape<RiscvAirId>> = serde_json::from_slice(SMALL_SHAPES).unwrap();

        // Set the allowed preprocessed log2 heights.
        let allowed_preprocessed_log2_heights = HashMap::from([
            (RiscvAirId::Program, vec![Some(19), Some(20), Some(21), Some(22)]),
            (RiscvAirId::Byte, vec![Some(16)]),
        ]);

        // Generate the clusters from the maximal shapes and register them indexed by log2 shard
        //  size.
        let blacklist = [
            27, 33, 47, 68, 75, 102, 104, 114, 116, 118, 137, 138, 139, 144, 145, 153, 155, 157,
            158, 169, 170, 171, 184, 185, 187, 195, 216, 243, 252, 275, 281, 282, 285,
        ];
        let mut core_allowed_log2_heights = BTreeMap::new();
        for (log2_shard_size, maximal_shapes) in maximal_shapes {
            let mut clusters = vec![];

            for (i, maximal_shape) in maximal_shapes.iter().enumerate() {
                // WARNING: This must be tuned carefully.
                //
                // This is current hardcoded, but in the future it should be computed dynamically.
                if log2_shard_size == 21 && blacklist.contains(&i) {
                    continue;
                }

                let cluster = derive_cluster_from_maximal_shape(maximal_shape);
                clusters.push(cluster);
            }

            core_allowed_log2_heights.insert(log2_shard_size, clusters);
        }

        // Set the memory init and finalize heights.
        let memory_allowed_log2_heights = HashMap::from(
            [
                (
                    RiscvAirId::MemoryGlobalInit,
                    vec![None, Some(10), Some(16), Some(18), Some(19), Some(20), Some(21)],
                ),
                (
                    RiscvAirId::MemoryGlobalFinalize,
                    vec![None, Some(10), Some(16), Some(18), Some(19), Some(20), Some(21)],
                ),
                (RiscvAirId::Global, vec![None, Some(11), Some(17), Some(19), Some(21), Some(22)]),
            ]
            .map(|(air, log_heights)| (air, log_heights)),
        );

        let mut precompile_allowed_log2_heights = HashMap::new();
        let precompile_heights = (3..21).collect::<Vec<_>>();
        for (air, memory_events_per_row) in
            RiscvAir::<F>::precompile_airs_with_memory_events_per_row()
        {
            precompile_allowed_log2_heights
                .insert(air, (memory_events_per_row, precompile_heights.clone()));
        }

        Self {
            partial_preprocessed_shapes: ShapeCluster::new(allowed_preprocessed_log2_heights),
            partial_core_shapes: core_allowed_log2_heights,
            partial_memory_shapes: ShapeCluster::new(memory_allowed_log2_heights),
            partial_precompile_shapes: precompile_allowed_log2_heights,
            partial_small_shapes: small_shapes
                .into_iter()
                .map(|x| {
                    ShapeCluster::new(x.into_iter().map(|(k, v)| (k, vec![Some(v)])).collect())
                })
                .collect(),
            costs: serde_json::from_str(include_str!("rv32im_costs.json")).unwrap(),
        }
    }
}

fn derive_cluster_from_maximal_shape(shape: &Shape<RiscvAirId>) -> ShapeCluster<RiscvAirId> {
    // We first define a heuristic to derive the log heights from the maximal shape.
    let log2_gap_from_21 = 21 - shape.log2_height(&RiscvAirId::Cpu).unwrap();
    let min_log2_height_threshold = 18 - log2_gap_from_21;
    let log2_height_buffer = 10;
    let heuristic = |maximal_log2_height: Option<usize>, min_offset: usize| {
        if let Some(maximal_log2_height) = maximal_log2_height {
            let tallest_log2_height = std::cmp::max(maximal_log2_height, min_log2_height_threshold);
            let shortest_log2_height = tallest_log2_height.saturating_sub(min_offset);

            let mut range =
                (shortest_log2_height..=tallest_log2_height).map(Some).collect::<Vec<_>>();

            if shortest_log2_height > maximal_log2_height {
                range.insert(0, Some(shortest_log2_height));
            }

            range
        } else {
            vec![None, Some(log2_height_buffer)]
        }
    };

    let mut maybe_log2_heights = HashMap::new();

    let cpu_log_height = shape.log2_height(&RiscvAirId::Cpu);
    maybe_log2_heights.insert(RiscvAirId::Cpu, heuristic(cpu_log_height, 0));

    let addsub_log_height = shape.log2_height(&RiscvAirId::AddSub);
    maybe_log2_heights.insert(RiscvAirId::AddSub, heuristic(addsub_log_height, 0));

    let lt_log_height = shape.log2_height(&RiscvAirId::Lt);
    maybe_log2_heights.insert(RiscvAirId::Lt, heuristic(lt_log_height, 0));

    let memory_local_log_height = shape.log2_height(&RiscvAirId::MemoryLocal);
    maybe_log2_heights.insert(RiscvAirId::MemoryLocal, heuristic(memory_local_log_height, 0));

    let divrem_log_height = shape.log2_height(&RiscvAirId::DivRem);
    maybe_log2_heights.insert(RiscvAirId::DivRem, heuristic(divrem_log_height, 1));

    let bitwise_log_height = shape.log2_height(&RiscvAirId::Bitwise);
    maybe_log2_heights.insert(RiscvAirId::Bitwise, heuristic(bitwise_log_height, 1));

    let mul_log_height = shape.log2_height(&RiscvAirId::Mul);
    maybe_log2_heights.insert(RiscvAirId::Mul, heuristic(mul_log_height, 1));

    let shift_right_log_height = shape.log2_height(&RiscvAirId::ShiftRight);
    maybe_log2_heights.insert(RiscvAirId::ShiftRight, heuristic(shift_right_log_height, 1));

    let shift_left_log_height = shape.log2_height(&RiscvAirId::ShiftLeft);
    maybe_log2_heights.insert(RiscvAirId::ShiftLeft, heuristic(shift_left_log_height, 1));

    let memory_instrs_log_height = shape.log2_height(&RiscvAirId::MemoryInstrs);
    maybe_log2_heights.insert(RiscvAirId::MemoryInstrs, heuristic(memory_instrs_log_height, 0));

    let auipc_log_height = shape.log2_height(&RiscvAirId::Auipc);
    maybe_log2_heights.insert(RiscvAirId::Auipc, heuristic(auipc_log_height, 0));

    let branch_log_height = shape.log2_height(&RiscvAirId::Branch);
    maybe_log2_heights.insert(RiscvAirId::Branch, heuristic(branch_log_height, 0));

    let jump_log_height = shape.log2_height(&RiscvAirId::Jump);
    maybe_log2_heights.insert(RiscvAirId::Jump, heuristic(jump_log_height, 0));

    let syscall_core_log_height = shape.log2_height(&RiscvAirId::SyscallCore);
    maybe_log2_heights.insert(RiscvAirId::SyscallCore, heuristic(syscall_core_log_height, 0));

    let syscall_instrs_log_height = shape.log2_height(&RiscvAirId::SyscallInstrs);
    maybe_log2_heights.insert(RiscvAirId::SyscallInstrs, heuristic(syscall_instrs_log_height, 0));

    let global_log_height = shape.log2_height(&RiscvAirId::Global);
    maybe_log2_heights.insert(RiscvAirId::Global, heuristic(global_log_height, 1));

    assert!(maybe_log2_heights.len() >= shape.len(), "not all chips were included in the shape");

    ShapeCluster::new(maybe_log2_heights)
}

#[derive(Debug, Error)]
pub enum CoreShapeError {
    #[error("no preprocessed shape found")]
    PreprocessedShapeError,
    #[error("Preprocessed shape already fixed")]
    PreprocessedShapeAlreadyFixed,
    #[error("no shape found {0:?}")]
    ShapeError(HashMap<String, usize>),
    #[error("Preprocessed shape missing")]
    PrepcocessedShapeMissing,
    #[error("Shape already fixed")]
    ShapeAlreadyFixed,
    #[error("Precompile not included in allowed shapes {0:?}")]
    PrecompileNotIncluded(HashMap<String, usize>),
}

pub fn create_dummy_program(shape: &Shape<RiscvAirId>) -> Program {
    let mut program = Program::new(vec![], 1 << 5, 1 << 5);
    program.preprocessed_shape = Some(shape.clone());
    program
}

pub fn create_dummy_record(shape: &Shape<RiscvAirId>) -> ExecutionRecord {
    let program = std::sync::Arc::new(create_dummy_program(shape));
    let mut record = ExecutionRecord::new(program);
    record.shape = Some(shape.clone());
    record
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::print_stdout)]

    use hashbrown::HashSet;
    use sp1_stark::{Dom, MachineProver, StarkGenericConfig};

    use super::*;

    fn try_generate_dummy_proof<SC: StarkGenericConfig, P: MachineProver<SC, RiscvAir<SC::Val>>>(
        prover: &P,
        shape: &Shape<RiscvAirId>,
    ) where
        SC::Val: PrimeField32,
        Dom<SC>: core::fmt::Debug,
    {
        let program = create_dummy_program(shape);
        let record = create_dummy_record(shape);

        // Try doing setup.
        let (pk, _) = prover.setup(&program);

        // Try to generate traces.
        let main_traces = prover.generate_traces(&record);

        // Try to commit the traces.
        let main_data = prover.commit(&record, main_traces);

        let mut challenger = prover.machine().config().challenger();

        // Try to "open".
        prover.open(&pk, main_data, &mut challenger).unwrap();
    }

    #[test]
    #[ignore]
    fn test_making_shapes() {
        use p3_baby_bear::BabyBear;
        let shape_config = CoreShapeConfig::<BabyBear>::default();
        let num_shapes = shape_config.all_shapes().collect::<HashSet<_>>().len();
        println!("There are {} core shapes", num_shapes);
        assert!(num_shapes < 1 << 24);
    }

    #[test]
    fn test_dummy_record() {
        use crate::utils::setup_logger;
        use p3_baby_bear::BabyBear;
        use sp1_stark::{baby_bear_poseidon2::BabyBearPoseidon2, CpuProver};

        type SC = BabyBearPoseidon2;
        type A = RiscvAir<BabyBear>;

        setup_logger();

        let preprocessed_log_heights = [(RiscvAirId::Program, 10), (RiscvAirId::Byte, 16)];

        let core_log_heights = [
            (RiscvAirId::Cpu, 11),
            (RiscvAirId::DivRem, 11),
            (RiscvAirId::AddSub, 10),
            (RiscvAirId::Bitwise, 10),
            (RiscvAirId::Mul, 10),
            (RiscvAirId::ShiftRight, 10),
            (RiscvAirId::ShiftLeft, 10),
            (RiscvAirId::Lt, 10),
            (RiscvAirId::MemoryLocal, 10),
            (RiscvAirId::SyscallCore, 10),
            (RiscvAirId::Global, 10),
        ];

        let height_map =
            preprocessed_log_heights.into_iter().chain(core_log_heights).collect::<HashMap<_, _>>();

        let shape = Shape::new(height_map);

        // Try generating preprocessed traces.
        let config = SC::default();
        let machine = A::machine(config);
        let prover = CpuProver::new(machine);

        try_generate_dummy_proof(&prover, &shape);
    }
}
