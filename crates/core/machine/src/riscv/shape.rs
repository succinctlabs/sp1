use itertools::Itertools;

use hashbrown::HashMap;
use num::Integer;
use p3_field::PrimeField32;
use p3_util::log2_ceil_usize;
use sp1_core_executor::{CoreShape, ExecutionRecord, Program};
use sp1_stark::{air::MachineAir, MachineRecord, ProofShape};
use thiserror::Error;

use crate::{
    memory::{MemoryLocalChip, MemoryProgramChip, NUM_LOCAL_MEMORY_ENTRIES_PER_ROW},
    riscv::MemoryChipType::{Finalize, Initialize},
};

use super::{
    AddSubChip, BitwiseChip, ByteChip, CpuChip, DivRemChip, LtChip, MemoryGlobalChip, MulChip,
    ProgramChip, RiscvAir, ShiftLeft, ShiftRightChip, SyscallChip,
};

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

/// A structure that enables fixing the shape of an executionrecord.
pub struct CoreShapeConfig<F: PrimeField32> {
    included_shapes: Vec<HashMap<String, usize>>,
    allowed_preprocessed_log_heights: HashMap<RiscvAir<F>, Vec<Option<usize>>>,
    allowed_core_log_heights: Vec<HashMap<RiscvAir<F>, Vec<Option<usize>>>>,
    maximal_core_log_heights_mask: Vec<bool>,
    memory_allowed_log_heights: HashMap<RiscvAir<F>, Vec<Option<usize>>>,
    precompile_allowed_log_heights: HashMap<RiscvAir<F>, (usize, Vec<usize>)>,
}

struct CoreShapeSpec {
    cpu_height: Vec<Option<usize>>,
    add_sub_height: Vec<Option<usize>>,
    divrem_height: Vec<Option<usize>>,
    bitwise_height: Vec<Option<usize>>,
    mul_height: Vec<Option<usize>>,
    shift_right_height: Vec<Option<usize>>,
    shift_left_height: Vec<Option<usize>>,
    lt_height: Vec<Option<usize>>,
    memory_local_height: Vec<Option<usize>>,
    syscall_core_height: Vec<Option<usize>>,
    is_potentially_maximal: bool,
}

impl<F: PrimeField32> CoreShapeConfig<F> {
    /// Fix the preprocessed shape of the proof.
    pub fn fix_preprocessed_shape(&self, program: &mut Program) -> Result<(), CoreShapeError> {
        if program.preprocessed_shape.is_some() {
            return Err(CoreShapeError::PreprocessedShapeAlreadyFixed);
        }

        let heights = RiscvAir::<F>::preprocessed_heights(program);
        let prep_shape =
            Self::find_shape_from_allowed_heights(&heights, &self.allowed_preprocessed_log_heights)
                .ok_or(CoreShapeError::PreprocessedShapeError)?;

        program.preprocessed_shape = Some(prep_shape);
        Ok(())
    }

    #[inline]
    fn find_shape_from_allowed_heights(
        heights: &[(RiscvAir<F>, usize)],
        allowed_log_heights: &HashMap<RiscvAir<F>, Vec<Option<usize>>>,
    ) -> Option<CoreShape> {
        let shape: Option<HashMap<String, usize>> = heights
            .iter()
            .map(|(air, height)| {
                for maybe_allowed_log_height in allowed_log_heights.get(air).into_iter().flatten() {
                    let allowed_log_height = maybe_allowed_log_height.unwrap_or_default();
                    let allowed_height =
                        if allowed_log_height != 0 { 1 << allowed_log_height } else { 0 };
                    if *height <= allowed_height {
                        return Some((air.name(), allowed_log_height));
                    }
                }
                None
            })
            .collect();

        let mut inner = shape?;
        inner.retain(|_, &mut value| value != 0);

        let shape = CoreShape { inner };
        Some(shape)
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

        // If cpu is included, try to fix the shape as a core.
        if record.contains_cpu() {
            // If cpu is included, try to fix the shape as a core.

            // Get the heights of the core airs in the record.
            let heights = RiscvAir::<F>::core_heights(record);

            // Try to find a shape within the included shapes.
            for (i, allowed_log_heights) in self.allowed_core_log_heights.iter().enumerate() {
                if let Some(shape) =
                    Self::find_shape_from_allowed_heights(&heights, allowed_log_heights)
                {
                    tracing::debug!(
                        "Shard Lifted: Index={}, Cluster={}",
                        record.public_values.shard,
                        i
                    );
                    for (air, height) in heights.iter() {
                        if shape.inner.contains_key(&air.name()) {
                            tracing::debug!(
                                "Chip {:<20}: {:<3} -> {:<3}",
                                air.name(),
                                log2_ceil_usize(*height),
                                shape.inner[&air.name()],
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

        // If the record is a global memory init/finalize record, try to fix the shape as such.
        if !record.global_memory_initialize_events.is_empty()
            || !record.global_memory_finalize_events.is_empty()
        {
            let heights = RiscvAir::<F>::get_memory_init_final_heights(record);
            let shape =
                Self::find_shape_from_allowed_heights(&heights, &self.memory_allowed_log_heights)
                    .ok_or(CoreShapeError::ShapeError(record.stats()))?;
            record.shape.as_mut().unwrap().extend(shape);
            return Ok(());
        }

        // Try to fix the shape as a precompile record.
        for (air, (mem_events_per_row, allowed_log_heights)) in
            self.precompile_allowed_log_heights.iter()
        {
            if let Some((height, mem_events)) = air.get_precompile_heights(record) {
                for allowed_log_height in allowed_log_heights {
                    if height <= (1 << allowed_log_height) {
                        for shape in self.get_precompile_shapes(
                            air,
                            *mem_events_per_row,
                            *allowed_log_height,
                        ) {
                            let mem_events_height = shape[2].1;
                            if mem_events
                                <= (1 << mem_events_height) * NUM_LOCAL_MEMORY_ENTRIES_PER_ROW
                            {
                                record.shape.as_mut().unwrap().extend(shape);
                                return Ok(());
                            }
                        }
                        return Ok(());
                    }
                }
                tracing::warn!(
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
    ) -> Vec<[(String, usize); 3]> {
        (1..=air.rows_per_event())
            .rev()
            .map(|rows_per_event| {
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
                        (((1 << allowed_log_height) * mem_events_per_row)
                            .div_ceil(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW * rows_per_event)
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
            .iter()
            .map(|(air, heights)| (air.name(), heights.clone()));

        let mut memory_heights = self
            .memory_allowed_log_heights
            .iter()
            .map(|(air, heights)| (air.name(), heights.clone()))
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
            .chain(self.allowed_core_log_heights.iter().flat_map(move |allowed_log_heights| {
                Self::generate_all_shapes_from_allowed_log_heights({
                    let mut log_heights = allowed_log_heights
                        .iter()
                        .map(|(air, heights)| (air.name(), heights.clone()))
                        .collect::<HashMap<_, _>>();
                    log_heights.extend(preprocessed_heights.clone());
                    log_heights
                })
            }))
            .chain(Self::generate_all_shapes_from_allowed_log_heights(memory_heights))
            .chain(precompile_shapes)
    }

    pub fn maximal_core_shapes(&self) -> Vec<CoreShape> {
        let max_preprocessed = self
            .allowed_preprocessed_log_heights
            .iter()
            .map(|(air, allowed_heights)| (air.name(), allowed_heights.last().unwrap().unwrap()));

        let max_core_shapes = self
            .allowed_core_log_heights
            .iter()
            .zip(self.maximal_core_log_heights_mask.iter())
            .filter(|(_, mask)| **mask)
            .map(|(allowed_log_heights, _)| {
                max_preprocessed
                    .clone()
                    .chain(allowed_log_heights.iter().map(|(air, allowed_heights)| {
                        (air.name(), allowed_heights.last().unwrap().unwrap())
                    }))
                    .collect::<CoreShape>()
            });

        max_core_shapes.collect()
    }
}

impl<F: PrimeField32> Default for CoreShapeConfig<F> {
    fn default() -> Self {
        // Preprocessed chip heights.
        let program_heights = vec![Some(19), Some(20), Some(21), Some(22)];
        let program_memory_heights = vec![Some(19), Some(20), Some(21), Some(22)];

        let allowed_preprocessed_log_heights = HashMap::from([
            (RiscvAir::Program(ProgramChip::default()), program_heights),
            (RiscvAir::ProgramMemory(MemoryProgramChip::default()), program_memory_heights),
            (RiscvAir::ByteLookup(ByteChip::default()), vec![Some(16)]),
        ]);

        let core_shapes = [
            // Small program shapes: 2^14 -> 2^18.
            CoreShapeSpec {
                cpu_height: vec![Some(14)],
                add_sub_height: vec![Some(14)],
                lt_height: vec![Some(14)],
                bitwise_height: vec![Some(14)],
                shift_right_height: vec![Some(14)],
                shift_left_height: vec![Some(14)],
                syscall_core_height: vec![Some(14)],
                memory_local_height: vec![Some(14)],
                mul_height: vec![Some(14)],
                divrem_height: vec![Some(14)],
                is_potentially_maximal: false,
            },
            CoreShapeSpec {
                cpu_height: vec![Some(15)],
                add_sub_height: vec![Some(15)],
                lt_height: vec![Some(15)],
                bitwise_height: vec![Some(15)],
                shift_right_height: vec![Some(15)],
                shift_left_height: vec![Some(15)],
                syscall_core_height: vec![Some(15)],
                memory_local_height: vec![Some(15)],
                mul_height: vec![Some(15)],
                divrem_height: vec![Some(15)],
                is_potentially_maximal: false,
            },
            CoreShapeSpec {
                cpu_height: vec![Some(16)],
                add_sub_height: vec![Some(16)],
                lt_height: vec![Some(16)],
                bitwise_height: vec![Some(16)],
                shift_right_height: vec![Some(16)],
                shift_left_height: vec![Some(16)],
                syscall_core_height: vec![Some(16)],
                memory_local_height: vec![Some(16)],
                mul_height: vec![Some(16)],
                divrem_height: vec![Some(16)],
                is_potentially_maximal: false,
            },
            CoreShapeSpec {
                cpu_height: vec![Some(17)],
                add_sub_height: vec![Some(17)],
                lt_height: vec![Some(17)],
                bitwise_height: vec![Some(17)],
                shift_right_height: vec![Some(17)],
                shift_left_height: vec![Some(17)],
                syscall_core_height: vec![Some(17)],
                memory_local_height: vec![Some(17)],
                mul_height: vec![Some(17)],
                divrem_height: vec![Some(17)],
                is_potentially_maximal: false,
            },
            CoreShapeSpec {
                cpu_height: vec![Some(18)],
                add_sub_height: vec![Some(18)],
                lt_height: vec![Some(18)],
                bitwise_height: vec![Some(18)],
                shift_right_height: vec![Some(18)],
                shift_left_height: vec![Some(18)],
                syscall_core_height: vec![Some(18)],
                memory_local_height: vec![Some(18)],
                mul_height: vec![Some(18)],
                divrem_height: vec![Some(18)],
                is_potentially_maximal: false,
            },
            // Small 2^19 shape variants.
            CoreShapeSpec {
                cpu_height: vec![Some(19)],
                add_sub_height: vec![Some(21)],
                lt_height: vec![Some(16)],
                bitwise_height: vec![Some(16)],
                shift_right_height: vec![Some(16)],
                shift_left_height: vec![Some(16)],
                syscall_core_height: vec![Some(16)],
                memory_local_height: vec![Some(16)],
                mul_height: vec![Some(16)],
                divrem_height: vec![Some(16)],
                is_potentially_maximal: false,
            },
            CoreShapeSpec {
                cpu_height: vec![Some(19)],
                add_sub_height: vec![Some(20)],
                lt_height: vec![Some(20)],
                bitwise_height: vec![Some(16)],
                shift_right_height: vec![Some(16)],
                shift_left_height: vec![Some(16)],
                syscall_core_height: vec![Some(16)],
                memory_local_height: vec![Some(16)],
                mul_height: vec![Some(16)],
                divrem_height: vec![Some(16)],
                is_potentially_maximal: false,
            },
            CoreShapeSpec {
                cpu_height: vec![Some(19)],
                add_sub_height: vec![Some(19)],
                lt_height: vec![Some(19)],
                bitwise_height: vec![Some(19)],
                shift_right_height: vec![Some(19)],
                shift_left_height: vec![Some(19)],
                syscall_core_height: vec![Some(19)],
                memory_local_height: vec![Some(19)],
                mul_height: vec![Some(19)],
                divrem_height: vec![Some(19)],
                is_potentially_maximal: false,
            },
            // All no-add chips in <= 1<<19.
            //
            // Most shapes should be included in this cluster.
            CoreShapeSpec {
                cpu_height: vec![Some(21)],
                add_sub_height: vec![Some(21)],
                lt_height: vec![Some(19)],
                bitwise_height: vec![Some(18), Some(19)],
                shift_right_height: vec![Some(16), Some(17), Some(18), Some(19)],
                shift_left_height: vec![Some(16), Some(17), Some(18), Some(19)],
                syscall_core_height: vec![Some(16), Some(17), Some(18)],
                memory_local_height: vec![Some(16), Some(18), Some(18)],
                mul_height: vec![Some(10), Some(16), Some(18)],
                divrem_height: vec![Some(10), Some(16), Some(17)],
                is_potentially_maximal: true,
            },
            CoreShapeSpec {
                cpu_height: vec![Some(21)],
                add_sub_height: vec![Some(21)],
                lt_height: vec![Some(20)],
                bitwise_height: vec![None, Some(18), Some(19)],
                shift_right_height: vec![None, Some(16), Some(17)],
                shift_left_height: vec![None, Some(16), Some(17)],
                syscall_core_height: vec![Some(16), Some(17)],
                memory_local_height: vec![Some(16), Some(18), Some(18)],
                mul_height: vec![None, Some(10), Some(16), Some(18)],
                divrem_height: vec![None, Some(10), Some(16), Some(17)],
                is_potentially_maximal: true,
            },
            CoreShapeSpec {
                cpu_height: vec![Some(21)],
                add_sub_height: vec![Some(21)],
                lt_height: vec![Some(19)],
                bitwise_height: vec![Some(17), Some(18)],
                shift_right_height: vec![Some(16), Some(17), Some(18), Some(19)],
                shift_left_height: vec![Some(16), Some(17), Some(18), Some(19)],
                syscall_core_height: vec![Some(16), Some(17), Some(19)],
                memory_local_height: vec![Some(16), Some(18), Some(19)],
                mul_height: vec![Some(10), Some(16), Some(18)],
                divrem_height: vec![Some(10), Some(16), Some(17)],
                is_potentially_maximal: true,
            },
            CoreShapeSpec {
                cpu_height: vec![Some(21)],
                add_sub_height: vec![Some(21)],
                lt_height: vec![Some(19)],
                bitwise_height: vec![Some(17), Some(18)],
                shift_right_height: vec![Some(16), Some(17), Some(18), Some(19)],
                shift_left_height: vec![Some(16), Some(17), Some(18), Some(19)],
                syscall_core_height: vec![Some(16), Some(17), Some(19)],
                memory_local_height: vec![Some(16), Some(18), Some(19)],
                mul_height: vec![Some(10), Some(16), Some(18)],
                divrem_height: vec![Some(10), Some(16), Some(17)],
                is_potentially_maximal: true,
            },
            CoreShapeSpec {
                cpu_height: vec![Some(21)],
                add_sub_height: vec![Some(19), Some(20)],
                lt_height: vec![Some(19)],
                bitwise_height: vec![Some(20)],
                shift_right_height: vec![Some(16), Some(17), Some(18), Some(19)],
                shift_left_height: vec![Some(16), Some(17), Some(18), Some(19)],
                syscall_core_height: vec![Some(16), Some(17), Some(19)],
                memory_local_height: vec![Some(16), Some(18), Some(19)],
                mul_height: vec![Some(10), Some(16), Some(18)],
                divrem_height: vec![Some(10), Some(16), Some(17)],
                is_potentially_maximal: true,
            },
            // LT in <= 1<<20
            //
            // For records with a lot of `LT` instructions, but less than 1<<20, this cluster is
            // appropriate.
            CoreShapeSpec {
                cpu_height: vec![Some(21)],
                add_sub_height: vec![Some(21)],
                lt_height: vec![Some(20)],
                bitwise_height: vec![Some(17), Some(18)],
                shift_right_height: vec![Some(17), Some(18)],
                shift_left_height: vec![Some(17), Some(18)],
                syscall_core_height: vec![Some(17), Some(18)],
                memory_local_height: vec![Some(16), Some(18), Some(19)],
                mul_height: vec![Some(10), Some(16), Some(18)],
                divrem_height: vec![Some(10), Some(16), Some(17)],
                is_potentially_maximal: true,
            },
            CoreShapeSpec {
                cpu_height: vec![Some(21)],
                add_sub_height: vec![Some(20)],
                lt_height: vec![Some(20)],
                bitwise_height: vec![Some(17), Some(18), Some(19)],
                shift_right_height: vec![Some(17), Some(18)],
                shift_left_height: vec![Some(17), Some(18)],
                syscall_core_height: vec![Some(17), Some(18)],
                memory_local_height: vec![Some(16), Some(18), Some(19)],
                mul_height: vec![Some(10), Some(16), Some(18)],
                divrem_height: vec![Some(10), Some(16), Some(17)],
                is_potentially_maximal: true,
            },
            // LT in <= 1<<21
            //
            // For records with a lot of `LT` instructions, and more than 1<<20, this cluster is
            // appropriate.
            CoreShapeSpec {
                cpu_height: vec![Some(21)],
                add_sub_height: vec![Some(21)],
                lt_height: vec![Some(21)],
                bitwise_height: vec![Some(17)],
                shift_right_height: vec![Some(17)],
                shift_left_height: vec![Some(17)],
                syscall_core_height: vec![Some(17)],
                memory_local_height: vec![Some(16), Some(18)],
                mul_height: vec![Some(10), Some(16), Some(18)],
                divrem_height: vec![Some(10), Some(16), Some(17)],
                is_potentially_maximal: true,
            },
            // Bitwise in <= 1<<20
            CoreShapeSpec {
                cpu_height: vec![Some(21)],
                add_sub_height: vec![Some(21)],
                lt_height: vec![Some(19)],
                bitwise_height: vec![Some(20)],
                shift_right_height: vec![Some(19)],
                shift_left_height: vec![Some(19)],
                syscall_core_height: vec![Some(18)],
                memory_local_height: vec![Some(16), Some(18)],
                mul_height: vec![Some(10), Some(16), Some(18)],
                divrem_height: vec![Some(10), Some(16)],
                is_potentially_maximal: true,
            },
            // Bitwise in <= 1<<21
            CoreShapeSpec {
                cpu_height: vec![Some(21)],
                add_sub_height: vec![Some(21)],
                lt_height: vec![Some(17)],
                bitwise_height: vec![Some(21)],
                shift_right_height: vec![Some(17)],
                shift_left_height: vec![Some(17)],
                syscall_core_height: vec![Some(16), Some(17)],
                memory_local_height: vec![Some(16), Some(18)],
                mul_height: vec![Some(10), Some(16), Some(18)],
                divrem_height: vec![Some(10), Some(16), Some(17)],
                is_potentially_maximal: true,
            },
            // SLL in <= 1<<20
            CoreShapeSpec {
                cpu_height: vec![Some(21)],
                add_sub_height: vec![Some(18)],
                lt_height: vec![Some(20)],
                bitwise_height: vec![Some(18)],
                shift_right_height: vec![Some(18)],
                shift_left_height: vec![Some(20)],
                syscall_core_height: vec![Some(16), Some(18)],
                memory_local_height: vec![Some(16), Some(18), Some(19)],
                mul_height: vec![Some(10), Some(16), Some(18)],
                divrem_height: vec![Some(10), Some(16), Some(17)],
                is_potentially_maximal: true,
            },
            // SLL in <= 1<<21
            CoreShapeSpec {
                cpu_height: vec![Some(21)],
                add_sub_height: vec![Some(21)],
                lt_height: vec![Some(17)],
                bitwise_height: vec![Some(17)],
                shift_right_height: vec![Some(17)],
                shift_left_height: vec![Some(21)],
                syscall_core_height: vec![Some(17)],
                memory_local_height: vec![Some(16), Some(18)],
                mul_height: vec![Some(10), Some(16), Some(18)],
                divrem_height: vec![Some(10), Some(16), Some(17)],
                is_potentially_maximal: true,
            },
            // SRL in <= 1<<20
            CoreShapeSpec {
                cpu_height: vec![Some(21)],
                add_sub_height: vec![Some(18)],
                lt_height: vec![Some(20)],
                bitwise_height: vec![Some(18)],
                shift_right_height: vec![Some(20)],
                shift_left_height: vec![Some(19)],
                syscall_core_height: vec![Some(18)],
                memory_local_height: vec![Some(16), Some(18), Some(19)],
                mul_height: vec![Some(10), Some(16), Some(18)],
                divrem_height: vec![Some(10), Some(16), Some(17)],
                is_potentially_maximal: true,
            },
            // Shards with basic arithmetic and branching.
            CoreShapeSpec {
                cpu_height: vec![Some(21)],
                add_sub_height: vec![Some(21)],
                lt_height: vec![Some(19)],
                bitwise_height: vec![Some(6)],
                shift_right_height: vec![Some(19)],
                shift_left_height: vec![Some(6)],
                syscall_core_height: vec![Some(6)],
                memory_local_height: vec![Some(16)],
                mul_height: vec![Some(19)],
                divrem_height: vec![Some(6)],
                is_potentially_maximal: true,
            },
            // Shards with many mul events.
            CoreShapeSpec {
                cpu_height: vec![Some(21)],
                add_sub_height: vec![Some(21)],
                lt_height: vec![Some(20)],
                bitwise_height: vec![Some(17), Some(18)],
                shift_right_height: vec![Some(17)],
                shift_left_height: vec![Some(17)],
                syscall_core_height: vec![Some(16)],
                memory_local_height: vec![Some(16)],
                mul_height: vec![Some(19), Some(20)],
                divrem_height: vec![Some(10), Some(16)],
                is_potentially_maximal: true,
            },
        ];

        let mut allowed_core_log_heights = vec![];
        let mut maximal_core_log_heights_mask = vec![];
        for spec in core_shapes {
            let short_allowed_log_heights = HashMap::from([
                (RiscvAir::Cpu(CpuChip::default()), spec.cpu_height),
                (RiscvAir::Add(AddSubChip::default()), spec.add_sub_height),
                (RiscvAir::Bitwise(BitwiseChip::default()), spec.bitwise_height),
                (RiscvAir::DivRem(DivRemChip::default()), spec.divrem_height),
                (RiscvAir::Mul(MulChip::default()), spec.mul_height),
                (RiscvAir::ShiftRight(ShiftRightChip::default()), spec.shift_right_height),
                (RiscvAir::ShiftLeft(ShiftLeft::default()), spec.shift_left_height),
                (RiscvAir::Lt(LtChip::default()), spec.lt_height),
                (RiscvAir::MemoryLocal(MemoryLocalChip::new()), spec.memory_local_height),
                (RiscvAir::SyscallCore(SyscallChip::core()), spec.syscall_core_height),
            ]);
            allowed_core_log_heights.push(short_allowed_log_heights);
            maximal_core_log_heights_mask.push(spec.is_potentially_maximal);
        }

        // Set the memory init and finalize heights.
        let memory_init_heights =
            vec![None, Some(10), Some(16), Some(18), Some(19), Some(20), Some(21)];
        let memory_finalize_heights =
            vec![None, Some(10), Some(16), Some(18), Some(19), Some(20), Some(21)];
        let memory_allowed_log_heights = HashMap::from([
            (RiscvAir::MemoryGlobalInit(MemoryGlobalChip::new(Initialize)), memory_init_heights),
            (RiscvAir::MemoryGlobalFinal(MemoryGlobalChip::new(Finalize)), memory_finalize_heights),
        ]);

        let mut precompile_allowed_log_heights = HashMap::new();
        let precompile_heights = (3..19).collect::<Vec<_>>();
        for (air, mem_events_per_row) in RiscvAir::<F>::get_all_precompile_airs() {
            precompile_allowed_log_heights
                .insert(air, (mem_events_per_row, precompile_heights.clone()));
        }

        Self {
            included_shapes: vec![],
            allowed_preprocessed_log_heights,
            allowed_core_log_heights,
            maximal_core_log_heights_mask,
            memory_allowed_log_heights,
            precompile_allowed_log_heights,
        }
    }
}

#[cfg(any(test, feature = "programs"))]
pub mod tests {
    use std::fmt::Debug;

    use p3_challenger::{CanObserve, FieldChallenger};
    use sp1_stark::{air::InteractionScope, Dom, MachineProver, StarkGenericConfig};

    use super::*;

    pub fn try_generate_dummy_proof<
        SC: StarkGenericConfig,
        P: MachineProver<SC, RiscvAir<SC::Val>>,
    >(
        prover: &P,
        shape: &CoreShape,
    ) where
        SC::Val: PrimeField32,
        Dom<SC>: Debug,
    {
        let program = shape.dummy_program();
        let record = shape.dummy_record();

        // Try doing setup.
        let (pk, _) = prover.setup(&program);

        // Try to generate traces.
        let global_traces = prover.generate_traces(&record, InteractionScope::Global);
        let local_traces = prover.generate_traces(&record, InteractionScope::Local);

        // Try to commit the traces.
        let global_data = prover.commit(&record, global_traces);
        let local_data = prover.commit(&record, local_traces);

        let mut challenger = prover.machine().config().challenger();
        challenger.observe(global_data.main_commit.clone());
        challenger.observe(local_data.main_commit.clone());

        let global_permutation_challenges: [<SC as StarkGenericConfig>::Challenge; 2] =
            [challenger.sample_ext_element(), challenger.sample_ext_element()];

        // Try to "open".
        prover
            .open(
                &pk,
                Some(global_data),
                local_data,
                &mut challenger,
                &global_permutation_challenges,
            )
            .unwrap();
    }

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
        use sp1_stark::baby_bear_poseidon2::BabyBearPoseidon2;
        use sp1_stark::CpuProver;

        type SC = BabyBearPoseidon2;
        type A = RiscvAir<BabyBear>;

        setup_logger();

        let preprocessed_log_heights = [
            (RiscvAir::<BabyBear>::Program(ProgramChip::default()), 10),
            (RiscvAir::<BabyBear>::ProgramMemory(MemoryProgramChip::default()), 10),
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
