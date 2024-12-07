use std::collections::BTreeMap;
use std::hash::Hash;
use std::str::FromStr;

use hashbrown::HashMap;
use itertools::Itertools;
use num::Integer;
use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;
use p3_util::log2_ceil_usize;
use serde::{Deserialize, Serialize};
use sp1_core_executor::{ExecutionRecord, MaximalShapes, Program, RiscvAirId, Shape};
use sp1_stark::{
    air::MachineAir, Dom, MachineProver, MachineRecord, ProofShape, StarkGenericConfig,
};
use thiserror::Error;

use crate::{
    global::GlobalChip,
    memory::{MemoryLocalChip, NUM_LOCAL_MEMORY_ENTRIES_PER_ROW},
    riscv::MemoryChipType::{Finalize, Initialize},
};

use super::{
    AddSubChip, BitwiseChip, ByteChip, CpuChip, DivRemChip, LtChip, MemoryGlobalChip, MulChip,
    ProgramChip, RiscvAir, ShiftLeft, ShiftRightChip, SyscallChip,
};

/// The set of maximal shapes.
///
/// These shapes define the "worst-case" shapes for typical shards that are proving `rv32im`
/// execution. We use a variant of a cartesian product of the allowed log heights to generate
/// smaller shapes from these ones.
const MAXIMAL_SHAPES: &[u8] = include_bytes!("../../maximal_shapes.json");

// /// The set of average shapes.
// ///
// /// These shapes define the "average" shapes for typical shards that are proving `rv32im`
// /// execution. We then use a heuristic algorihtm to generate them.
// const AVERAGE_SHAPES: &[u8] = include_bytes!("../../average_shapes.json");

/// The minimum log height threshold for allowed log heights.
const MIN_LOG_HEIGHT_THRESHOLD: usize = 18;

/// The log height buffer.
const LOG_HEIGHT_BUFFER: usize = 10;

/// A structure that enables fixing the shape of an execution record.
pub struct CoreShapeConfig<F: PrimeField32> {
    included_shapes: Vec<HashMap<RiscvAirId, u64>>,
    shapes_with_cpu_and_memory_finalize: Vec<ShapeCluster<RiscvAirId>>,
    allowed_preprocessed_log_heights: ShapeCluster<RiscvAirId>,
    allowed_core_log_heights: BTreeMap<usize, Vec<ShapeCluster<RiscvAirId>>>,
    memory_allowed_log_heights: ShapeCluster<RiscvAirId>,
    precompile_allowed_log_heights: HashMap<RiscvAir<F>, (usize, Vec<usize>)>,
    core_costs: HashMap<String, u64>,
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ShapeCluster<K: Eq + Hash + FromStr> {
    maybe_log2_heights: HashMap<K, Vec<Option<usize>>>,
}

impl<K: Clone + Eq + Hash + FromStr> ShapeCluster<K> {
    fn new(maybe_log2_heights: HashMap<K, Vec<Option<usize>>>) -> Self {
        Self { maybe_log2_heights }
    }

    fn find_shape(&self, heights: &[(K, usize)]) -> Option<Shape<K>> {
        // Find the shape that is larger or equal to the given heights.
        let shape: Option<HashMap<K, Option<usize>>> = heights
            .iter()
            .map(|(air, height)| {
                for maybe_log2_height in self.maybe_log2_heights.get(air).into_iter().flatten() {
                    let allowed_height =
                        maybe_log2_height.map(|log_height| 1 << log_height).unwrap_or_default();
                    if *height <= allowed_height {
                        return Some((air.clone(), *maybe_log2_height));
                    }
                }
                None
            })
            .collect();

        let mut inner = shape?;
        inner.retain(|_, &mut value| value.is_some());

        let shape = inner
            .into_iter()
            .map(|(air, maybe_log_height)| (air, maybe_log_height.unwrap()))
            .collect::<Shape<K>>();

        Some(shape)
    }

    #[inline]
    fn range(
        log_max_height: Option<usize>,
        min_offset: usize,
        _optional: bool,
    ) -> Vec<Option<usize>> {
        if let Some(log_max_height) = log_max_height {
            let log_height = std::cmp::max(log_max_height, MIN_LOG_HEIGHT_THRESHOLD);
            let min_log_height = log_height.saturating_sub(min_offset);

            let mut range = (min_log_height..=log_height).map(Some).collect::<Vec<_>>();

            if min_log_height > log_max_height {
                range.insert(0, Some(min_log_height));
            }
            range
        } else {
            vec![None, Some(LOG_HEIGHT_BUFFER)]
        }
    }
}

impl ShapeCluster<RiscvAirId> {
    fn from_maximal_shape(shape: &Shape<RiscvAirId>) -> Self {
        let mut log_heights = HashMap::new();

        let cpu_log_height = shape.get(&RiscvAirId::Cpu);
        log_heights.insert(RiscvAirId::Cpu, Self::range(cpu_log_height, 0, false));

        let addsub_log_height = shape.get(&RiscvAirId::AddSub);
        log_heights.insert(RiscvAirId::AddSub, Self::range(addsub_log_height, 0, false));

        let lt_log_height = shape.get(&RiscvAirId::Lt);
        log_heights.insert(RiscvAirId::Lt, Self::range(lt_log_height, 0, false));

        let memory_local_log_height = shape.get(&RiscvAirId::MemoryLocal);
        log_heights.insert(RiscvAirId::MemoryLocal, Self::range(memory_local_log_height, 0, false));

        let divrem_log_height = shape.get(&RiscvAirId::DivRem);
        log_heights.insert(RiscvAirId::DivRem, Self::range(divrem_log_height, 1, true));

        let bitwise_log_height = shape.get(&RiscvAirId::Bitwise);
        log_heights.insert(RiscvAirId::Bitwise, Self::range(bitwise_log_height, 1, false));

        let mul_log_height = shape.get(&RiscvAirId::Mul);
        log_heights.insert(RiscvAirId::Mul, Self::range(mul_log_height, 1, true));

        let shift_right_log_height = shape.get(&RiscvAirId::ShiftRight);
        log_heights.insert(RiscvAirId::ShiftRight, Self::range(shift_right_log_height, 1, true));

        let shift_left_log_height = shape.get(&RiscvAirId::ShiftLeft);
        log_heights.insert(RiscvAirId::ShiftLeft, Self::range(shift_left_log_height, 1, true));

        let memory_instrs_log_height = shape.get(&RiscvAirId::MemoryInstrs);
        log_heights
            .insert(RiscvAirId::MemoryInstrs, Self::range(memory_instrs_log_height, 0, true));

        let auipc_log_height = shape.get(&RiscvAirId::Auipc);
        log_heights.insert(RiscvAirId::Auipc, Self::range(auipc_log_height, 0, true));

        let branch_log_height = shape.get(&RiscvAirId::Branch);
        log_heights.insert(RiscvAirId::Branch, Self::range(branch_log_height, 0, true));

        let jump_log_height = shape.get(&RiscvAirId::Jump);
        log_heights.insert(RiscvAirId::Jump, Self::range(jump_log_height, 0, false));

        let syscall_core_log_height = shape.get(&RiscvAirId::SyscallCore);
        log_heights.insert(RiscvAirId::SyscallCore, Self::range(syscall_core_log_height, 0, true));

        let syscall_instrs_log_height = shape.get(&RiscvAirId::SyscallInstrs);
        log_heights
            .insert(RiscvAirId::SyscallInstrs, Self::range(syscall_instrs_log_height, 0, true));

        let global_log_height = shape.get(&RiscvAirId::Global);
        log_heights.insert(RiscvAirId::Global, Self::range(global_log_height, 1, false));

        assert!(log_heights.len() >= shape.len(), "not all chips were included in the shape");

        Self { maybe_log2_heights: log_heights }
    }
}

impl<F: PrimeField32> CoreShapeConfig<F> {
    /// Fix the preprocessed shape of the proof.
    pub fn fix_preprocessed_shape(&self, program: &mut Program) -> Result<(), CoreShapeError> {
        if program.preprocessed_shape.is_some() {
            return Err(CoreShapeError::PreprocessedShapeAlreadyFixed);
        }

        let heights = RiscvAir::<F>::preprocessed_heights(program)
            .into_iter()
            .map(|(air, height)| (RiscvAirId::from_str(&air).unwrap(), height))
            .collect::<Vec<_>>();
        let prep_shape = self
            .allowed_preprocessed_log_heights
            .find_shape(&heights)
            .ok_or(CoreShapeError::PreprocessedShapeError)?;

        program.preprocessed_shape = Some(prep_shape);
        Ok(())
    }

    fn trace_area(&self, shape: &Shape<RiscvAirId>) -> u64 {
        shape.iter().map(|(air, height)| self.core_costs[&air.to_string()] * *height).sum()
    }

    pub fn small_program_shapes(&self) -> Vec<ProofShape> {
        self.shapes_with_cpu_and_memory_finalize
            .iter()
            .map(|log_heights| {
                ProofShape::from_log2_heights(
                    &log_heights
                        .maybe_log2_heights
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

        // If the record has global memory init/finalize events, the candidates are shapes that
        // include the memory initialize/finalize chip.
        if record.contains_cpu()
            && (!record.global_memory_finalize_events.is_empty()
                || !record.global_memory_initialize_events.is_empty())
        {
            // Get the heights of the core airs in the record.
            let mut heights = RiscvAir::<F>::core_heights(record);
            heights.extend(RiscvAir::<F>::get_memory_init_final_heights(record));
            let heights = heights
                .into_iter()
                .map(|(air, height)| (RiscvAirId::from_str(&air).unwrap(), height))
                .collect::<Vec<_>>();

            // Try to find a shape fitting within at least one of the candidate shapes.
            for (i, allowed_log_heights) in
                self.shapes_with_cpu_and_memory_finalize.iter().enumerate()
            {
                if let Some(shape) = allowed_log_heights.find_shape(&heights) {
                    tracing::info!(
                        "Shard Lifted: Index={}, Cluster={}",
                        record.public_values.shard,
                        i
                    );
                    for (air, height) in heights.iter() {
                        if shape.contains(air) {
                            tracing::info!(
                                "Chip {:<20}: {:<3} -> {:<3}",
                                air,
                                log2_ceil_usize(*height),
                                shape.get(air).unwrap(),
                            );
                        }
                    }

                    record.shape.as_mut().unwrap().extend(shape);
                    return Ok(());
                }
            }

            // No shape found, so return an error.
            return Err(CoreShapeError::ShapeError(record.stats()));
        }

        // If cpu is included, try to fix the shape as a core.
        if record.contains_cpu() {
            // If cpu is included, try to fix the shape as a core.

            // Get the heights of the core airs in the record.
            let heights = RiscvAir::<F>::core_heights(record);
            let heights = heights
                .into_iter()
                .map(|(air, height)| (RiscvAirId::from_str(&air).unwrap(), height))
                .collect::<Vec<_>>();

            // Iterate over all included shapes and see if there is a match. A match is defined as
            // the shape containing the air and the height being less than or equal to than
            // 1 << shape[air].
            let found_shape = self
                .included_shapes
                .iter()
                .find(|shape| {
                    for (air, height) in heights.iter() {
                        if !shape.contains_key(air) || *height > (1 << shape.get(air).unwrap()) {
                            return false;
                        }
                    }
                    true
                })
                .cloned();

            if let Some(shape) = found_shape {
                tracing::warn!("Found shape in included shapes");
                record.shape.as_mut().unwrap().extend(shape);
                return Ok(());
            }

            let log_shard_size = record.cpu_events.len().next_power_of_two().ilog2() as usize;
            tracing::debug!("log_shard_size: {log_shard_size}");

            let mut found_shape = None;
            let mut found_area = u64::MAX;
            let mut found_cluster = None;
            for (_, shape_candidates) in self.allowed_core_log_heights.range(log_shard_size..) {
                // Try to find a shape fitting within at least one of the candidate shapes.
                for (i, allowed_log_heights) in shape_candidates.iter().enumerate() {
                    if let Some(shape) = allowed_log_heights.find_shape(&heights) {
                        if self.trace_area(&shape) < found_area {
                            found_area = self.trace_area(&shape);
                            found_shape = Some(shape);
                            found_cluster = Some(i);
                        }
                    }
                }
            }

            if let Some(shape) = found_shape {
                tracing::info!(
                    "Shard Lifted: Index={}, cluster = {}",
                    record.public_values.shard,
                    found_cluster.unwrap()
                );
                for (air, height) in heights.iter() {
                    if shape.contains(air) {
                        tracing::info!(
                            "Chip {:<20}: {:<3} -> {:<3}",
                            air,
                            log2_ceil_usize(*height),
                            shape.get(air).unwrap(),
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
            let heights = RiscvAir::<F>::get_memory_init_final_heights(record);
            let heights = heights
                .into_iter()
                .map(|(air, height)| (RiscvAirId::from_str(&air).unwrap(), height))
                .collect::<Vec<_>>();
            let shape = self
                .memory_allowed_log_heights
                .find_shape(&heights)
                .ok_or(CoreShapeError::ShapeError(record.stats()))?;
            record.shape.as_mut().unwrap().extend(shape);
            return Ok(());
        }

        // Try to fix the shape as a precompile record.
        for (air, (mem_events_per_row, allowed_log_heights)) in
            self.precompile_allowed_log_heights.iter()
        {
            if let Some((height, mem_events, global_events)) = air.get_precompile_heights(record) {
                for allowed_log_height in allowed_log_heights {
                    if height <= (1 << allowed_log_height) {
                        for shape in self.get_precompile_shapes(
                            air,
                            *mem_events_per_row,
                            *allowed_log_height,
                        ) {
                            let mem_events_height = shape[2].1;
                            let global_events_height = shape[3].1;
                            if mem_events.div_ceil(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW)
                                <= (1 << mem_events_height)
                                && global_events <= (1 << global_events_height)
                            {
                                record.shape.as_mut().unwrap().extend(shape);
                                return Ok(());
                            }
                        }
                    }
                }
                tracing::error!(
                    "Cannot find shape for precompile {:?}, height {:?}, and mem events {:?}",
                    air.name(),
                    height,
                    mem_events
                );
                return Err(CoreShapeError::ShapeError(record.stats()));
            }
        }
        Err(CoreShapeError::PrecompileNotIncluded(record.stats()))
    }

    fn get_precompile_shapes(
        &self,
        air: &RiscvAir<F>,
        mem_events_per_row: usize,
        allowed_log_height: usize,
    ) -> Vec<[(String, usize); 4]> {
        // TODO: this is a temporary fix to the shape, concretely fix this
        (1..=4 * air.rows_per_event())
            .rev()
            .map(|rows_per_event| {
                let num_local_mem_events =
                    ((1 << allowed_log_height) * mem_events_per_row).div_ceil(rows_per_event);
                [
                    (air.name(), allowed_log_height),
                    (
                        RiscvAir::<F>::SyscallPrecompile(SyscallChip::precompile()).name(),
                        ((1 << allowed_log_height)
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
                            + (1 << allowed_log_height).div_ceil(&air.rows_per_event()))
                        .next_power_of_two()
                        .ilog2() as usize)
                            .max(4),
                    ),
                ]
            })
            .collect()
    }

    fn generate_all_shapes_from_allowed_log_heights(
        allowed_log_heights: impl IntoIterator<Item = (String, Vec<Option<usize>>)>,
    ) -> impl Iterator<Item = ProofShape> {
        // for chip in allowed_heights.
        allowed_log_heights
            .into_iter()
            .map(|(name, heights)| heights.into_iter().map(move |height| (name.clone(), height)))
            .multi_cartesian_product()
            .map(|iter| {
                iter.into_iter()
                    .filter_map(|(name, maybe_height)| {
                        maybe_height.map(|log_height| (name, log_height))
                    })
                    .collect::<ProofShape>()
            })
    }

    pub fn generate_all_allowed_shapes(&self) -> impl Iterator<Item = ProofShape> + '_ {
        let preprocessed_heights = self
            .allowed_preprocessed_log_heights
            .maybe_log2_heights
            .iter()
            .map(|(air, heights)| (air.to_string(), heights.clone()));

        let mut memory_heights = self
            .memory_allowed_log_heights
            .maybe_log2_heights
            .iter()
            .map(|(air, heights)| (air.to_string(), heights.clone()))
            .collect::<HashMap<_, _>>();
        memory_heights.extend(preprocessed_heights.clone());

        let included_shapes = self.included_shapes.iter().cloned().map(|map| {
            map.into_iter()
                .map(|(air, log_height)| (air.to_string(), log_height as usize))
                .collect::<ProofShape>()
        });

        let precompile_only_shapes = self.precompile_allowed_log_heights.iter().flat_map(
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
                            .collect::<ProofShape>()
                    })
                });

        included_shapes
            .chain(self.allowed_core_log_heights.values().flatten().flat_map(
                move |allowed_log_heights| {
                    Self::generate_all_shapes_from_allowed_log_heights({
                        let mut log_heights = allowed_log_heights
                            .maybe_log2_heights
                            .iter()
                            .map(|(air, heights)| (air.to_string(), heights.clone()))
                            .collect::<HashMap<_, _>>();
                        log_heights.extend(preprocessed_heights.clone());
                        log_heights
                    })
                },
            ))
            .chain(Self::generate_all_shapes_from_allowed_log_heights(memory_heights))
            .chain(precompile_shapes)
    }

    pub fn maximal_core_shapes(&self, max_log_shard_size: usize) -> Vec<Shape<RiscvAirId>> {
        let max_shard_size: usize = core::cmp::max(
            1 << max_log_shard_size,
            1 << self.allowed_core_log_heights.keys().min().unwrap(),
        );

        let log_shard_size = max_shard_size.ilog2() as usize;
        debug_assert_eq!(1 << log_shard_size, max_shard_size);
        let max_preprocessed = self.allowed_preprocessed_log_heights.maybe_log2_heights.iter().map(
            |(air, allowed_heights)| (air.to_string(), allowed_heights.last().unwrap().unwrap()),
        );

        let max_core_shapes =
            self.allowed_core_log_heights[&log_shard_size].iter().map(|allowed_log_heights| {
                max_preprocessed
                    .clone()
                    .chain(allowed_log_heights.maybe_log2_heights.iter().flat_map(
                        |(air, allowed_heights)| {
                            allowed_heights
                                .last()
                                .unwrap()
                                .map(|log_height| (air.to_string(), log_height))
                        },
                    ))
                    .map(|(air, log_height)| (RiscvAirId::from_str(&air).unwrap(), log_height))
                    .collect::<Shape<RiscvAirId>>()
            });

        max_core_shapes.collect()
    }

    pub fn maximal_core_plus_precompile_shapes(
        &self,
        max_log_shard_size: usize,
    ) -> Vec<Shape<RiscvAirId>> {
        let max_preprocessed = self.allowed_preprocessed_log_heights.maybe_log2_heights.iter().map(
            |(air, allowed_heights)| (air.to_string(), allowed_heights.last().unwrap().unwrap()),
        );

        let precompile_only_shapes = self.precompile_allowed_log_heights.iter().flat_map(
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
                    .chain(x)
                    .map(|(air, log_height)| (RiscvAirId::from_str(&air).unwrap(), log_height))
                    .collect::<Shape<RiscvAirId>>()
            })
            .filter(|shape| shape.get(&RiscvAirId::Global).unwrap() < 21)
            .collect();

        self.maximal_core_shapes(max_log_shard_size).into_iter().chain(precompile_shapes).collect()
    }
}

impl<F: PrimeField32> Default for CoreShapeConfig<F> {
    fn default() -> Self {
        let maximal_core_shapes: MaximalShapes<RiscvAirId> =
            serde_json::from_slice(MAXIMAL_SHAPES).unwrap();
        // let included_shapes: Vec<HashMap<String, usize>> =
        //     serde_json::from_slice(AVERAGE_SHAPES).unwrap();
        let included_shapes: Vec<HashMap<RiscvAirId, u64>> = vec![];

        // Preprocessed chip heights.
        let program_heights = vec![Some(19), Some(20), Some(21), Some(22)];

        let allowed_preprocessed_log_heights = HashMap::from([
            (RiscvAirId::Program, program_heights),
            (RiscvAirId::Byte, vec![Some(16)]),
        ]);

        let mut allowed_core_log_heights = BTreeMap::new();

        for (log_shard_size, maximal_shapes) in maximal_core_shapes.shard_map {
            let mut core_log_heights: Vec<ShapeCluster<RiscvAirId>> = vec![];
            let mut maximal_core_log_heights_mask = vec![];
            for shape in maximal_shapes.shapes {
                core_log_heights.push(ShapeCluster::from_maximal_shape(&shape));
                maximal_core_log_heights_mask.push(true);
            }
            allowed_core_log_heights.insert(log_shard_size, core_log_heights);
        }

        // Set the memory init and finalize heights.
        let memory_init_heights =
            vec![None, Some(10), Some(16), Some(18), Some(19), Some(20), Some(21)];
        let memory_finalize_heights =
            vec![None, Some(10), Some(16), Some(18), Some(19), Some(20), Some(21)];
        let global_heights = vec![None, Some(11), Some(17), Some(19), Some(21), Some(22)];
        let memory_allowed_log_heights = HashMap::from(
            [
                (RiscvAirId::MemoryGlobalInit, memory_init_heights),
                (RiscvAirId::MemoryGlobalFinalize, memory_finalize_heights),
                (RiscvAirId::Global, global_heights),
            ]
            .map(|(air, log_heights)| (air, log_heights)),
        );

        let mut precompile_allowed_log_heights = HashMap::new();
        let precompile_heights = (3..19).collect::<Vec<_>>();
        for (air, mem_events_per_row) in RiscvAir::<F>::get_all_precompile_airs() {
            precompile_allowed_log_heights
                .insert(air, (mem_events_per_row, precompile_heights.clone()));
        }

        // Shapes for shards with a CPU chip and memory initialize/finalize events.
        let shapes_with_cpu_and_memory_finalize = vec![
            // Small shape with few Muls and LTs.
            HashMap::from([
                (RiscvAirId::Cpu, vec![Some(13)]),
                (RiscvAirId::AddSub, vec![Some(12)]),
                (RiscvAirId::Bitwise, vec![Some(11)]),
                (RiscvAirId::Mul, vec![Some(4)]),
                (RiscvAirId::ShiftRight, vec![Some(10)]),
                (RiscvAirId::ShiftLeft, vec![Some(10)]),
                (RiscvAirId::Lt, vec![Some(8)]),
                (RiscvAirId::MemoryLocal, vec![Some(6)]),
                (RiscvAirId::Global, vec![Some(16)]),
                (RiscvAirId::SyscallCore, vec![None]),
                (RiscvAirId::DivRem, vec![None]),
                (RiscvAirId::MemoryGlobalInit, vec![Some(8)]),
                (RiscvAirId::MemoryGlobalFinalize, vec![Some(15)]),
            ]),
            // Small shape with few Muls.
            HashMap::from([
                (RiscvAirId::Cpu, vec![Some(14)]),
                (RiscvAirId::AddSub, vec![Some(14)]),
                (RiscvAirId::Bitwise, vec![Some(11)]),
                (RiscvAirId::Mul, vec![Some(4)]),
                (RiscvAirId::ShiftRight, vec![Some(10)]),
                (RiscvAirId::ShiftLeft, vec![Some(10)]),
                (RiscvAirId::Lt, vec![Some(13)]),
                (RiscvAirId::MemoryLocal, vec![Some(6)]),
                (RiscvAirId::Global, vec![Some(12)]),
                (RiscvAirId::SyscallCore, vec![None]),
                (RiscvAirId::DivRem, vec![None]),
                (RiscvAirId::MemoryGlobalInit, vec![Some(8)]),
                (RiscvAirId::MemoryGlobalFinalize, vec![Some(15)]),
            ]),
            // Small shape with many Muls.
            HashMap::from([
                (RiscvAirId::Cpu, vec![Some(15)]),
                (RiscvAirId::AddSub, vec![Some(14)]),
                (RiscvAirId::Bitwise, vec![Some(11)]),
                (RiscvAirId::Mul, vec![Some(12)]),
                (RiscvAirId::ShiftRight, vec![Some(12)]),
                (RiscvAirId::ShiftLeft, vec![Some(10)]),
                (RiscvAirId::Lt, vec![Some(12)]),
                (RiscvAirId::MemoryLocal, vec![Some(7)]),
                (RiscvAirId::Global, vec![Some(16)]),
                (RiscvAirId::SyscallCore, vec![None]),
                (RiscvAirId::DivRem, vec![None]),
                (RiscvAirId::MemoryGlobalInit, vec![Some(8)]),
                (RiscvAirId::MemoryGlobalFinalize, vec![Some(15)]),
            ]),
            // Medium shape with few muls.
            HashMap::from([
                (RiscvAirId::Cpu, vec![Some(17)]),
                (RiscvAirId::AddSub, vec![Some(17)]),
                (RiscvAirId::Bitwise, vec![Some(11)]),
                (RiscvAirId::Mul, vec![Some(4)]),
                (RiscvAirId::ShiftRight, vec![Some(10)]),
                (RiscvAirId::ShiftLeft, vec![Some(10)]),
                (RiscvAirId::Lt, vec![Some(16)]),
                (RiscvAirId::MemoryLocal, vec![Some(6)]),
                (RiscvAirId::Global, vec![Some(7)]),
                (RiscvAirId::SyscallCore, vec![None]),
                (RiscvAirId::DivRem, vec![None]),
                (RiscvAirId::MemoryGlobalInit, vec![Some(8)]),
                (RiscvAirId::MemoryGlobalFinalize, vec![Some(15)]),
            ]),
            // Medium shape with many Muls.
            HashMap::from([
                (RiscvAirId::Cpu, vec![Some(18)]),
                (RiscvAirId::AddSub, vec![Some(17)]),
                (RiscvAirId::Bitwise, vec![Some(11)]),
                (RiscvAirId::Mul, vec![Some(15)]),
                (RiscvAirId::ShiftRight, vec![Some(15)]),
                (RiscvAirId::ShiftLeft, vec![Some(10)]),
                (RiscvAirId::Lt, vec![Some(15)]),
                (RiscvAirId::MemoryLocal, vec![Some(7)]),
                (RiscvAirId::Global, vec![Some(11)]),
                (RiscvAirId::SyscallCore, vec![None]),
                (RiscvAirId::DivRem, vec![None]),
                (RiscvAirId::MemoryGlobalInit, vec![Some(8)]),
                (RiscvAirId::MemoryGlobalFinalize, vec![Some(15)]),
            ]),
            // Large shapes
            HashMap::from([
                (RiscvAirId::Cpu, vec![Some(20)]),
                (RiscvAirId::AddSub, vec![Some(20)]),
                (RiscvAirId::Bitwise, vec![Some(11)]),
                (RiscvAirId::Mul, vec![Some(4)]),
                (RiscvAirId::ShiftRight, vec![Some(10)]),
                (RiscvAirId::ShiftLeft, vec![Some(10)]),
                (RiscvAirId::Lt, vec![Some(19)]),
                (RiscvAirId::MemoryLocal, vec![Some(6)]),
                (RiscvAirId::Global, vec![Some(10)]),
                (RiscvAirId::SyscallCore, vec![None]),
                (RiscvAirId::DivRem, vec![None]),
                (RiscvAirId::MemoryGlobalInit, vec![Some(8)]),
                (RiscvAirId::MemoryGlobalFinalize, vec![Some(15)]),
            ]),
            HashMap::from([
                (RiscvAirId::Cpu, vec![Some(20)]),
                (RiscvAirId::AddSub, vec![Some(20)]),
                (RiscvAirId::Bitwise, vec![Some(11)]),
                (RiscvAirId::Mul, vec![Some(4)]),
                (RiscvAirId::ShiftRight, vec![Some(11)]),
                (RiscvAirId::ShiftLeft, vec![Some(10)]),
                (RiscvAirId::Lt, vec![Some(19)]),
                (RiscvAirId::MemoryLocal, vec![Some(6)]),
                (RiscvAirId::Global, vec![Some(10)]),
                (RiscvAirId::SyscallCore, vec![Some(3)]),
                (RiscvAirId::DivRem, vec![Some(3)]),
                (RiscvAirId::MemoryGlobalInit, vec![Some(8)]),
                (RiscvAirId::MemoryGlobalFinalize, vec![Some(15)]),
            ]),
            HashMap::from([
                (RiscvAirId::Cpu, vec![Some(21)]),
                (RiscvAirId::AddSub, vec![Some(21)]),
                (RiscvAirId::Bitwise, vec![Some(11)]),
                (RiscvAirId::Mul, vec![Some(19)]),
                (RiscvAirId::ShiftRight, vec![Some(19)]),
                (RiscvAirId::ShiftLeft, vec![Some(10)]),
                (RiscvAirId::Lt, vec![Some(19)]),
                (RiscvAirId::MemoryLocal, vec![Some(7)]),
                (RiscvAirId::Global, vec![Some(11)]),
                (RiscvAirId::SyscallCore, vec![None]),
                (RiscvAirId::DivRem, vec![None]),
                (RiscvAirId::MemoryGlobalInit, vec![Some(8)]),
                (RiscvAirId::MemoryGlobalFinalize, vec![Some(15)]),
            ]),
            // Catchall shape.
            HashMap::from([
                (RiscvAirId::Cpu, vec![Some(21)]),
                (RiscvAirId::AddSub, vec![Some(21)]),
                (RiscvAirId::Bitwise, vec![Some(19)]),
                (RiscvAirId::Mul, vec![Some(19)]),
                (RiscvAirId::ShiftRight, vec![Some(19)]),
                (RiscvAirId::ShiftLeft, vec![Some(19)]),
                (RiscvAirId::Lt, vec![Some(20)]),
                (RiscvAirId::MemoryLocal, vec![Some(19)]),
                (RiscvAirId::Global, vec![Some(10)]),
                (RiscvAirId::SyscallCore, vec![Some(19)]),
                (RiscvAirId::DivRem, vec![Some(21)]),
                (RiscvAirId::MemoryGlobalInit, vec![Some(19)]),
                (RiscvAirId::MemoryGlobalFinalize, vec![Some(19)]),
            ]),
        ];

        Self {
            included_shapes,
            allowed_preprocessed_log_heights: ShapeCluster::new(allowed_preprocessed_log_heights),
            allowed_core_log_heights,
            // maximal_core_log_heights_mask,
            memory_allowed_log_heights: ShapeCluster::new(memory_allowed_log_heights),
            precompile_allowed_log_heights,
            shapes_with_cpu_and_memory_finalize: shapes_with_cpu_and_memory_finalize
                .into_iter()
                .map(|log_heights| ShapeCluster::new(log_heights))
                .collect::<Vec<_>>(),
            core_costs: serde_json::from_str(include_str!(
                "../../../executor/src/artifacts/rv32im_costs.json"
            ))
            .unwrap(), // TODO: load from file
        }
    }
}

pub fn try_generate_dummy_proof<SC: StarkGenericConfig, P: MachineProver<SC, RiscvAir<SC::Val>>>(
    prover: &P,
    shape: &Shape<RiscvAirId>,
) where
    SC::Val: PrimeField32,
    Dom<SC>: core::fmt::Debug,
{
    let program = shape.dummy_program();
    let record = shape.dummy_record();

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

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test_making_shapes() {
        use p3_baby_bear::BabyBear;
        let shape_config = CoreShapeConfig::<BabyBear>::default();
        let num_shapes = shape_config.generate_all_allowed_shapes().count();
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

        let height_map = preprocessed_log_heights
            .into_iter()
            .chain(core_log_heights)
            .map(|(air, log_height)| (air, log_height))
            .collect::<HashMap<_, _>>();

        let shape = Shape::new(height_map);

        // Try generating preprocessed traces.
        let config = SC::default();
        let machine = A::machine(config);
        let prover = CpuProver::new(machine);

        try_generate_dummy_proof(&prover, &shape);
    }
}
