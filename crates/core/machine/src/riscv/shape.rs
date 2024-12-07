use std::collections::BTreeMap;

use hashbrown::HashMap;
use itertools::Itertools;
use num::Integer;
use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;
use p3_util::log2_ceil_usize;
use serde::{Deserialize, Serialize};
use sp1_core_executor::{CoreShape, ExecutionRecord, MaximalShapes, Program};
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
    included_shapes: Vec<HashMap<String, usize>>,
    shapes_with_cpu_and_memory_finalize: Vec<ShapeCluster<F>>,
    allowed_preprocessed_log_heights: ShapeCluster<F>,
    allowed_core_log_heights: BTreeMap<usize, Vec<ShapeCluster<F>>>,
    memory_allowed_log_heights: ShapeCluster<F>,
    precompile_allowed_log_heights: HashMap<RiscvAir<F>, (usize, Vec<usize>)>,
    core_costs: HashMap<String, usize>,
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
struct ShapeCluster<F> {
    log_heights: HashMap<String, Vec<Option<usize>>>,
    _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField32> ShapeCluster<F> {
    fn new(log_heights: HashMap<String, Vec<Option<usize>>>) -> Self {
        Self { log_heights, _marker: std::marker::PhantomData }
    }

    fn find_shape(&self, heights: &[(String, usize)]) -> Option<CoreShape> {
        // Find the shape that is larger or equal to the given heights.
        let shape: Option<HashMap<String, Option<usize>>> = heights
            .iter()
            .map(|(air, height)| {
                for maybe_allowed_log_height in self.log_heights.get(air).into_iter().flatten() {
                    let allowed_height = maybe_allowed_log_height
                        .map(|log_height| 1 << log_height)
                        .unwrap_or_default();
                    if *height <= allowed_height {
                        return Some((air.clone(), *maybe_allowed_log_height));
                    }
                }
                None
            })
            .collect();

        // Filter the shape so that HashMap<String, Option<usize>> becomes HashMap<String, usize>.
        let mut inner = shape?;
        inner.retain(|_, &mut value| value.is_some());
        let inner = inner
            .into_iter()
            .map(|(air, maybe_log_height)| (air, maybe_log_height.unwrap()))
            .collect();

        // Create the shape.
        let shape = CoreShape { inner };
        Some(shape)
    }

    #[inline]
    fn range(
        log_max_height: Option<&usize>,
        min_offset: usize,
        _optional: bool,
    ) -> Vec<Option<usize>> {
        if let Some(&log_max_height) = log_max_height {
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

    fn from_maximal_shape(shape: &CoreShape) -> Self {
        let mut log_heights = HashMap::new();

        let cpu_log_height = shape.inner.get("CPU");
        log_heights.insert("CPU".to_string(), Self::range(cpu_log_height, 0, false));
        let addsub_log_height = shape.inner.get("AddSub");
        log_heights.insert("AddSub".to_string(), Self::range(addsub_log_height, 0, false));
        let lt_log_height = shape.inner.get("Lt");
        log_heights.insert("Lt".to_string(), Self::range(lt_log_height, 0, false));
        let memory_local_log_height = shape.inner.get("MemoryLocal");
        log_heights
            .insert("MemoryLocal".to_string(), Self::range(memory_local_log_height, 0, false));
        let divrem_log_height = shape.inner.get("DivRem");
        log_heights.insert("DivRem".to_string(), Self::range(divrem_log_height, 1, true));
        let bitwise_log_height = shape.inner.get("Bitwise");
        log_heights.insert("Bitwise".to_string(), Self::range(bitwise_log_height, 1, false));
        let mul_log_height = shape.inner.get("Mul");
        log_heights.insert("Mul".to_string(), Self::range(mul_log_height, 1, true));
        let shift_right_log_height = shape.inner.get("ShiftRight");
        log_heights.insert("ShiftRight".to_string(), Self::range(shift_right_log_height, 1, true));
        let shift_left_log_height = shape.inner.get("ShiftLeft");
        log_heights.insert("ShiftLeft".to_string(), Self::range(shift_left_log_height, 1, true));

        let memory_instrs_log_height = shape.inner.get("MemoryInstrs");
        log_heights
            .insert("MemoryInstrs".to_string(), Self::range(memory_instrs_log_height, 0, true));
        let auipc_log_height = shape.inner.get("Auipc");
        log_heights.insert("Auipc".to_string(), Self::range(auipc_log_height, 0, true));
        let branch_log_height = shape.inner.get("Branch");
        log_heights.insert("Branch".to_string(), Self::range(branch_log_height, 0, true));
        let jump_log_height = shape.inner.get("Jump");
        log_heights.insert("Jump".to_string(), Self::range(jump_log_height, 0, false));
        let syscall_core_log_height = shape.inner.get("SyscallCore");
        log_heights
            .insert("SyscallCore".to_string(), Self::range(syscall_core_log_height, 0, true));
        let syscall_instrs_log_height = shape.inner.get("SyscallInstrs");
        log_heights
            .insert("SyscallInstrs".to_string(), Self::range(syscall_instrs_log_height, 0, true));

        let global_log_height = shape.inner.get("Global");
        log_heights.insert("Global".to_string(), Self::range(global_log_height, 1, false));

        assert!(log_heights.len() >= shape.inner.len(), "not all chips were included in the shape");

        Self { log_heights, _marker: std::marker::PhantomData }
    }
}

impl<F: PrimeField32> CoreShapeConfig<F> {
    /// Fix the preprocessed shape of the proof.
    pub fn fix_preprocessed_shape(&self, program: &mut Program) -> Result<(), CoreShapeError> {
        if program.preprocessed_shape.is_some() {
            return Err(CoreShapeError::PreprocessedShapeAlreadyFixed);
        }

        let heights = RiscvAir::<F>::preprocessed_heights(program);
        let prep_shape = self
            .allowed_preprocessed_log_heights
            .find_shape(&heights)
            .ok_or(CoreShapeError::PreprocessedShapeError)?;

        program.preprocessed_shape = Some(prep_shape);
        Ok(())
    }

    #[inline]
    fn trace_area(&self, shape: &CoreShape) -> usize {
        shape.inner.iter().map(|(air, height)| self.core_costs[air] * height).sum()
    }

    pub fn small_program_shapes(&self) -> Vec<ProofShape> {
        self.shapes_with_cpu_and_memory_finalize
            .iter()
            .map(|log_heights| {
                ProofShape::from_log2_heights(
                    &log_heights
                        .log_heights
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
                        if shape.inner.contains_key(air) {
                            tracing::info!(
                                "Chip {:<20}: {:<3} -> {:<3}",
                                air,
                                log2_ceil_usize(*height),
                                shape.inner[air],
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

            // Iterate over all included shapes and see if there is a match. A match is defined as
            // the shape containing the air and the height being less than or equal to than
            // 1 << shape[air].
            let found_shape = self
                .included_shapes
                .iter()
                .find(|shape| {
                    for (air, height) in heights.iter() {
                        if !shape.contains_key(air) || *height > (1 << shape[air]) {
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
            let mut found_area = usize::MAX;
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
                    if shape.inner.contains_key(air) {
                        tracing::info!(
                            "Chip {:<20}: {:<3} -> {:<3}",
                            air,
                            log2_ceil_usize(*height),
                            shape.inner[air],
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
            .log_heights
            .iter()
            .map(|(air, heights)| (air.to_string(), heights.clone()));

        let mut memory_heights = self
            .memory_allowed_log_heights
            .log_heights
            .iter()
            .map(|(air, heights)| (air.to_string(), heights.clone()))
            .collect::<HashMap<_, _>>();
        memory_heights.extend(preprocessed_heights.clone());

        let included_shapes =
            self.included_shapes.iter().cloned().map(|map| map.into_iter().collect::<ProofShape>());

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
                            .log_heights
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

    pub fn maximal_core_shapes(&self, max_log_shard_size: usize) -> Vec<CoreShape> {
        let max_shard_size: usize = core::cmp::max(
            1 << max_log_shard_size,
            1 << self.allowed_core_log_heights.keys().min().unwrap(),
        );

        let log_shard_size = max_shard_size.ilog2() as usize;
        debug_assert_eq!(1 << log_shard_size, max_shard_size);
        let max_preprocessed = self.allowed_preprocessed_log_heights.log_heights.iter().map(
            |(air, allowed_heights)| (air.to_string(), allowed_heights.last().unwrap().unwrap()),
        );

        let max_core_shapes =
            self.allowed_core_log_heights[&log_shard_size].iter().map(|allowed_log_heights| {
                max_preprocessed
                    .clone()
                    .chain(allowed_log_heights.log_heights.iter().flat_map(
                        |(air, allowed_heights)| {
                            allowed_heights
                                .last()
                                .unwrap()
                                .map(|log_height| (air.to_string(), log_height))
                        },
                    ))
                    .collect::<CoreShape>()
            });

        max_core_shapes.collect()
    }

    pub fn maximal_core_plus_precompile_shapes(&self, max_log_shard_size: usize) -> Vec<CoreShape> {
        let max_preprocessed = self.allowed_preprocessed_log_heights.log_heights.iter().map(
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

        let precompile_shapes: Vec<CoreShape> = precompile_only_shapes
            .map(|x| max_preprocessed.clone().chain(x).collect::<CoreShape>())
            .filter(|shape| shape.inner["Global"] < 21)
            .collect();

        self.maximal_core_shapes(max_log_shard_size).into_iter().chain(precompile_shapes).collect()
    }
}

impl<F: PrimeField32> Default for CoreShapeConfig<F> {
    fn default() -> Self {
        let maximal_core_shapes: MaximalShapes = serde_json::from_slice(MAXIMAL_SHAPES).unwrap();
        // let included_shapes: Vec<HashMap<String, usize>> =
        //     serde_json::from_slice(AVERAGE_SHAPES).unwrap();
        let included_shapes: Vec<HashMap<String, usize>> = vec![];

        // Preprocessed chip heights.
        let program_heights = vec![Some(19), Some(20), Some(21), Some(22)];

        let allowed_preprocessed_log_heights = HashMap::from([
            (RiscvAir::<F>::Program(ProgramChip::default()).name(), program_heights),
            (RiscvAir::<F>::ByteLookup(ByteChip::default()).name(), vec![Some(16)]),
        ]);

        let mut allowed_core_log_heights = BTreeMap::new();

        for (log_shard_size, maximal_shapes) in maximal_core_shapes.shard_map {
            let mut core_log_heights: Vec<ShapeCluster<F>> = vec![];
            let mut maximal_core_log_heights_mask = vec![];
            for shape in maximal_shapes {
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
                (
                    RiscvAir::<F>::MemoryGlobalInit(MemoryGlobalChip::new(Initialize)),
                    memory_init_heights,
                ),
                (
                    RiscvAir::<F>::MemoryGlobalFinal(MemoryGlobalChip::new(Finalize)),
                    memory_finalize_heights,
                ),
                (RiscvAir::<F>::Global(GlobalChip), global_heights),
            ]
            .map(|(air, log_heights)| (air.name(), log_heights)),
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
            HashMap::from(
                [
                    (RiscvAir::<F>::Cpu(CpuChip::default()), vec![Some(13)]),
                    (RiscvAir::<F>::Add(AddSubChip::default()), vec![Some(12)]),
                    (RiscvAir::<F>::Bitwise(BitwiseChip::default()), vec![Some(11)]),
                    (RiscvAir::<F>::Mul(MulChip::default()), vec![Some(4)]),
                    (RiscvAir::<F>::ShiftRight(ShiftRightChip::default()), vec![Some(10)]),
                    (RiscvAir::<F>::ShiftLeft(ShiftLeft::default()), vec![Some(10)]),
                    (RiscvAir::<F>::Lt(LtChip::default()), vec![Some(8)]),
                    (RiscvAir::<F>::MemoryLocal(MemoryLocalChip::new()), vec![Some(6)]),
                    (RiscvAir::<F>::Global(GlobalChip), vec![Some(16)]),
                    (RiscvAir::<F>::SyscallCore(SyscallChip::core()), vec![None]),
                    (RiscvAir::<F>::DivRem(DivRemChip::default()), vec![None]),
                    (
                        RiscvAir::<F>::MemoryGlobalInit(MemoryGlobalChip::new(Initialize)),
                        vec![Some(8)],
                    ),
                    (
                        RiscvAir::<F>::MemoryGlobalFinal(MemoryGlobalChip::new(Finalize)),
                        vec![Some(15)],
                    ),
                ]
                .map(|(air, log_heights)| (air.name(), log_heights)),
            ),
            // Small shape with few Muls.
            HashMap::from(
                [
                    (RiscvAir::<F>::Cpu(CpuChip::default()), vec![Some(14)]),
                    (RiscvAir::<F>::Add(AddSubChip::default()), vec![Some(14)]),
                    (RiscvAir::<F>::Bitwise(BitwiseChip::default()), vec![Some(11)]),
                    (RiscvAir::<F>::Mul(MulChip::default()), vec![Some(4)]),
                    (RiscvAir::<F>::ShiftRight(ShiftRightChip::default()), vec![Some(10)]),
                    (RiscvAir::<F>::ShiftLeft(ShiftLeft::default()), vec![Some(10)]),
                    (RiscvAir::<F>::Lt(LtChip::default()), vec![Some(13)]),
                    (RiscvAir::<F>::MemoryLocal(MemoryLocalChip::new()), vec![Some(6)]),
                    (RiscvAir::<F>::Global(GlobalChip), vec![Some(12)]),
                    (RiscvAir::<F>::SyscallCore(SyscallChip::core()), vec![None]),
                    (RiscvAir::<F>::DivRem(DivRemChip::default()), vec![None]),
                    (
                        RiscvAir::<F>::MemoryGlobalInit(MemoryGlobalChip::new(Initialize)),
                        vec![Some(8)],
                    ),
                    (
                        RiscvAir::<F>::MemoryGlobalFinal(MemoryGlobalChip::new(Finalize)),
                        vec![Some(15)],
                    ),
                ]
                .map(|(air, log_heights)| (air.name(), log_heights)),
            ),
            // Small shape with many Muls.
            HashMap::from(
                [
                    (RiscvAir::<F>::Cpu(CpuChip::default()), vec![Some(15)]),
                    (RiscvAir::<F>::Add(AddSubChip::default()), vec![Some(14)]),
                    (RiscvAir::<F>::Bitwise(BitwiseChip::default()), vec![Some(11)]),
                    (RiscvAir::<F>::Mul(MulChip::default()), vec![Some(12)]),
                    (RiscvAir::<F>::ShiftRight(ShiftRightChip::default()), vec![Some(12)]),
                    (RiscvAir::<F>::ShiftLeft(ShiftLeft::default()), vec![Some(10)]),
                    (RiscvAir::<F>::Lt(LtChip::default()), vec![Some(12)]),
                    (RiscvAir::<F>::MemoryLocal(MemoryLocalChip::new()), vec![Some(7)]),
                    (RiscvAir::<F>::Global(GlobalChip), vec![Some(16)]),
                    (RiscvAir::<F>::SyscallCore(SyscallChip::core()), vec![None]),
                    (RiscvAir::<F>::DivRem(DivRemChip::default()), vec![None]),
                    (
                        RiscvAir::<F>::MemoryGlobalInit(MemoryGlobalChip::new(Initialize)),
                        vec![Some(8)],
                    ),
                    (
                        RiscvAir::<F>::MemoryGlobalFinal(MemoryGlobalChip::new(Finalize)),
                        vec![Some(15)],
                    ),
                ]
                .map(|(air, log_heights)| (air.name(), log_heights)),
            ),
            // Medium shape with few muls.
            HashMap::from(
                [
                    (RiscvAir::<F>::Cpu(CpuChip::default()), vec![Some(17)]),
                    (RiscvAir::<F>::Add(AddSubChip::default()), vec![Some(17)]),
                    (RiscvAir::<F>::Bitwise(BitwiseChip::default()), vec![Some(11)]),
                    (RiscvAir::<F>::Mul(MulChip::default()), vec![Some(4)]),
                    (RiscvAir::<F>::ShiftRight(ShiftRightChip::default()), vec![Some(10)]),
                    (RiscvAir::<F>::ShiftLeft(ShiftLeft::default()), vec![Some(10)]),
                    (RiscvAir::<F>::Lt(LtChip::default()), vec![Some(16)]),
                    (RiscvAir::<F>::MemoryLocal(MemoryLocalChip::new()), vec![Some(6)]),
                    (RiscvAir::<F>::Global(GlobalChip), vec![Some(7)]),
                    (RiscvAir::<F>::SyscallCore(SyscallChip::core()), vec![None]),
                    (RiscvAir::<F>::DivRem(DivRemChip::default()), vec![None]),
                    (
                        RiscvAir::<F>::MemoryGlobalInit(MemoryGlobalChip::new(Initialize)),
                        vec![Some(8)],
                    ),
                    (
                        RiscvAir::<F>::MemoryGlobalFinal(MemoryGlobalChip::new(Finalize)),
                        vec![Some(15)],
                    ),
                ]
                .map(|(air, log_heights)| (air.name(), log_heights)),
            ),
            // Medium shape with many Muls.
            HashMap::from(
                [
                    (RiscvAir::<F>::Cpu(CpuChip::default()), vec![Some(18)]),
                    (RiscvAir::<F>::Add(AddSubChip::default()), vec![Some(17)]),
                    (RiscvAir::<F>::Bitwise(BitwiseChip::default()), vec![Some(11)]),
                    (RiscvAir::<F>::Mul(MulChip::default()), vec![Some(15)]),
                    (RiscvAir::<F>::ShiftRight(ShiftRightChip::default()), vec![Some(15)]),
                    (RiscvAir::<F>::ShiftLeft(ShiftLeft::default()), vec![Some(10)]),
                    (RiscvAir::<F>::Lt(LtChip::default()), vec![Some(15)]),
                    (RiscvAir::<F>::MemoryLocal(MemoryLocalChip::new()), vec![Some(7)]),
                    (RiscvAir::<F>::Global(GlobalChip), vec![Some(11)]),
                    (RiscvAir::<F>::SyscallCore(SyscallChip::core()), vec![None]),
                    (RiscvAir::<F>::DivRem(DivRemChip::default()), vec![None]),
                    (
                        RiscvAir::<F>::MemoryGlobalInit(MemoryGlobalChip::new(Initialize)),
                        vec![Some(8)],
                    ),
                    (
                        RiscvAir::<F>::MemoryGlobalFinal(MemoryGlobalChip::new(Finalize)),
                        vec![Some(15)],
                    ),
                ]
                .map(|(air, log_heights)| (air.name(), log_heights)),
            ),
            // Large shapes
            HashMap::from(
                [
                    (RiscvAir::<F>::Cpu(CpuChip::default()), vec![Some(20)]),
                    (RiscvAir::<F>::Add(AddSubChip::default()), vec![Some(20)]),
                    (RiscvAir::<F>::Bitwise(BitwiseChip::default()), vec![Some(11)]),
                    (RiscvAir::<F>::Mul(MulChip::default()), vec![Some(4)]),
                    (RiscvAir::<F>::ShiftRight(ShiftRightChip::default()), vec![Some(10)]),
                    (RiscvAir::<F>::ShiftLeft(ShiftLeft::default()), vec![Some(10)]),
                    (RiscvAir::<F>::Lt(LtChip::default()), vec![Some(19)]),
                    (RiscvAir::<F>::MemoryLocal(MemoryLocalChip::new()), vec![Some(6)]),
                    (RiscvAir::<F>::Global(GlobalChip), vec![Some(10)]),
                    (RiscvAir::<F>::SyscallCore(SyscallChip::core()), vec![None]),
                    (RiscvAir::<F>::DivRem(DivRemChip::default()), vec![None]),
                    (
                        RiscvAir::<F>::MemoryGlobalInit(MemoryGlobalChip::new(Initialize)),
                        vec![Some(8)],
                    ),
                    (
                        RiscvAir::<F>::MemoryGlobalFinal(MemoryGlobalChip::new(Finalize)),
                        vec![Some(15)],
                    ),
                ]
                .map(|(air, log_heights)| (air.name(), log_heights)),
            ),
            HashMap::from(
                [
                    (RiscvAir::<F>::Cpu(CpuChip::default()), vec![Some(20)]),
                    (RiscvAir::<F>::Add(AddSubChip::default()), vec![Some(20)]),
                    (RiscvAir::<F>::Bitwise(BitwiseChip::default()), vec![Some(11)]),
                    (RiscvAir::<F>::Mul(MulChip::default()), vec![Some(4)]),
                    (RiscvAir::<F>::ShiftRight(ShiftRightChip::default()), vec![Some(11)]),
                    (RiscvAir::<F>::ShiftLeft(ShiftLeft::default()), vec![Some(10)]),
                    (RiscvAir::<F>::Lt(LtChip::default()), vec![Some(19)]),
                    (RiscvAir::<F>::MemoryLocal(MemoryLocalChip::new()), vec![Some(6)]),
                    (RiscvAir::<F>::Global(GlobalChip), vec![Some(10)]),
                    (RiscvAir::<F>::SyscallCore(SyscallChip::core()), vec![Some(3)]),
                    (RiscvAir::<F>::DivRem(DivRemChip::default()), vec![Some(3)]),
                    (
                        RiscvAir::<F>::MemoryGlobalInit(MemoryGlobalChip::new(Initialize)),
                        vec![Some(8)],
                    ),
                    (
                        RiscvAir::<F>::MemoryGlobalFinal(MemoryGlobalChip::new(Finalize)),
                        vec![Some(15)],
                    ),
                ]
                .map(|(air, log_heights)| (air.name(), log_heights)),
            ),
            HashMap::from(
                [
                    (RiscvAir::<F>::Cpu(CpuChip::default()), vec![Some(21)]),
                    (RiscvAir::<F>::Add(AddSubChip::default()), vec![Some(21)]),
                    (RiscvAir::<F>::Bitwise(BitwiseChip::default()), vec![Some(11)]),
                    (RiscvAir::<F>::Mul(MulChip::default()), vec![Some(19)]),
                    (RiscvAir::<F>::ShiftRight(ShiftRightChip::default()), vec![Some(19)]),
                    (RiscvAir::<F>::ShiftLeft(ShiftLeft::default()), vec![Some(10)]),
                    (RiscvAir::<F>::Lt(LtChip::default()), vec![Some(19)]),
                    (RiscvAir::<F>::MemoryLocal(MemoryLocalChip::new()), vec![Some(7)]),
                    (RiscvAir::<F>::Global(GlobalChip), vec![Some(11)]),
                    (RiscvAir::<F>::SyscallCore(SyscallChip::core()), vec![None]),
                    (RiscvAir::<F>::DivRem(DivRemChip::default()), vec![None]),
                    (
                        RiscvAir::<F>::MemoryGlobalInit(MemoryGlobalChip::new(Initialize)),
                        vec![Some(8)],
                    ),
                    (
                        RiscvAir::<F>::MemoryGlobalFinal(MemoryGlobalChip::new(Finalize)),
                        vec![Some(15)],
                    ),
                ]
                .map(|(air, log_heights)| (air.name(), log_heights)),
            ),
            // Catchall shape.
            HashMap::from(
                [
                    (RiscvAir::<F>::Cpu(CpuChip::default()), vec![Some(21)]),
                    (RiscvAir::<F>::Add(AddSubChip::default()), vec![Some(21)]),
                    (RiscvAir::<F>::Bitwise(BitwiseChip::default()), vec![Some(19)]),
                    (RiscvAir::<F>::Mul(MulChip::default()), vec![Some(19)]),
                    (RiscvAir::<F>::ShiftRight(ShiftRightChip::default()), vec![Some(19)]),
                    (RiscvAir::<F>::ShiftLeft(ShiftLeft::default()), vec![Some(19)]),
                    (RiscvAir::<F>::Lt(LtChip::default()), vec![Some(20)]),
                    (RiscvAir::<F>::MemoryLocal(MemoryLocalChip::new()), vec![Some(19)]),
                    (RiscvAir::<F>::Global(GlobalChip), vec![Some(10)]),
                    (RiscvAir::<F>::SyscallCore(SyscallChip::core()), vec![Some(19)]),
                    (RiscvAir::<F>::DivRem(DivRemChip::default()), vec![Some(21)]),
                    (
                        RiscvAir::<F>::MemoryGlobalInit(MemoryGlobalChip::new(Initialize)),
                        vec![Some(19)],
                    ),
                    (
                        RiscvAir::<F>::MemoryGlobalFinal(MemoryGlobalChip::new(Finalize)),
                        vec![Some(19)],
                    ),
                ]
                .map(|(air, log_heights)| (air.name(), log_heights)),
            ),
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
    shape: &CoreShape,
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

        let preprocessed_log_heights = [
            (RiscvAir::<BabyBear>::Program(ProgramChip::default()), 10),
            (RiscvAir::<BabyBear>::ByteLookup(ByteChip::default()), 16),
        ];

        let core_log_heights = [
            (RiscvAir::<BabyBear>::Cpu(CpuChip::default()), 11),
            (RiscvAir::<BabyBear>::DivRem(DivRemChip::default()), 11),
            (RiscvAir::<BabyBear>::Add(AddSubChip::default()), 10),
            (RiscvAir::<BabyBear>::Bitwise(BitwiseChip::default()), 10),
            (RiscvAir::<BabyBear>::Mul(MulChip::default()), 10),
            (RiscvAir::<BabyBear>::ShiftRight(ShiftRightChip::default()), 10),
            (RiscvAir::<BabyBear>::ShiftLeft(ShiftLeft::default()), 10),
            (RiscvAir::<BabyBear>::Lt(LtChip::default()), 10),
            (RiscvAir::<BabyBear>::MemoryLocal(MemoryLocalChip::new()), 10),
            (RiscvAir::<BabyBear>::SyscallCore(SyscallChip::core()), 10),
            (RiscvAir::<BabyBear>::Global(GlobalChip), 10),
        ];

        let height_map = preprocessed_log_heights
            .into_iter()
            .chain(core_log_heights)
            .map(|(air, log_height)| (air.name(), log_height))
            .collect::<HashMap<_, _>>();

        let shape = CoreShape { inner: height_map };

        // Try generating preprocessed traces.
        let config = SC::default();
        let machine = A::machine(config);
        let prover = CpuProver::new(machine);

        try_generate_dummy_proof(&prover, &shape);
    }
}
