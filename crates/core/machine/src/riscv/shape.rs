use itertools::Itertools;

use hashbrown::{HashMap, HashSet};
use num::Integer;
use p3_field::PrimeField32;
use sp1_core_executor::{CoreShape, ExecutionRecord, Program};
use sp1_stark::{air::MachineAir, ProofShape};
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
    #[error("no shape found")]
    ShapeError,
    #[error("Preprocessed shape missing")]
    PrepcocessedShapeMissing,
    #[error("Shape already fixed")]
    ShapeAlreadyFixed,
    #[error("Precompile not included in allowed shapes")]
    PrecompileNotIncluded,
}

/// A structure that enables fixing the shape of an executionrecord.
pub struct CoreShapeConfig<F: PrimeField32> {
    included_shapes: Vec<HashMap<String, usize>>,
    allowed_preprocessed_log_heights: HashMap<RiscvAir<F>, Vec<Option<usize>>>,
    allowed_core_log_heights: Vec<(HashMap<RiscvAir<F>, Vec<Option<usize>>>, bool)>,
    memory_allowed_log_heights: HashMap<RiscvAir<F>, Vec<Option<usize>>>,
    precompile_allowed_log_heights: HashMap<RiscvAir<F>, (usize, Vec<usize>)>,
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
            .filter(|(_, height)| *height != 0)
            .map(|(air, height)| {
                for allowed_log_height in
                    allowed_log_heights.get(air).into_iter().flatten().flatten()
                {
                    let allowed_height = 1 << allowed_log_height;
                    if *height <= allowed_height {
                        return Some((air.name(), *allowed_log_height));
                    }
                }
                None
            })
            .collect();

        let shape = CoreShape { inner: shape? };
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
            for (allowed_log_heights, _) in self.allowed_core_log_heights.iter() {
                if let Some(shape) =
                    Self::find_shape_from_allowed_heights(&heights, allowed_log_heights)
                {
                    record.shape.as_mut().unwrap().extend(shape);
                    return Ok(());
                }
            }

            // No shape found, so return an error.
            return Err(CoreShapeError::ShapeError);
        }

        // If the record is a global memory init/finalize record, try to fix the shape as such.
        if !record.global_memory_initialize_events.is_empty()
            || !record.global_memory_finalize_events.is_empty()
        {
            let heights = RiscvAir::<F>::get_memory_init_final_heights(record);
            let shape =
                Self::find_shape_from_allowed_heights(&heights, &self.memory_allowed_log_heights)
                    .ok_or(CoreShapeError::ShapeError)?;
            record.shape.as_mut().unwrap().extend(shape);
            return Ok(());
        }

        // Try to fix the shape as a precompile record. Since we allow all possible
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
            }
        }
        tracing::warn!(
            "No shape found for the record with syscall events {:?}",
            record.syscall_events
        );

        Err(CoreShapeError::PrecompileNotIncluded)
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

        let cpu_name = || RiscvAir::<F>::Cpu(CpuChip::default()).name();
        let memory_local_name = || RiscvAir::<F>::MemoryLocal(MemoryLocalChip::new()).name();
        let syscall_name = || RiscvAir::<F>::SyscallCore(SyscallChip::core()).name();
        let core_filter = move |shape: &ProofShape| {
            let core_airs = RiscvAir::<F>::get_all_core_airs()
                .into_iter()
                .map(|air| air.name())
                .filter(|name| name != &memory_local_name() && name != &syscall_name())
                .collect::<HashSet<_>>();
            let core_chips_and_heights = shape
                .chip_information
                .iter()
                .filter(|(name, _)| core_airs.contains(name))
                .cloned()
                .collect::<Vec<_>>();

            let cpu_name = cpu_name();

            let biggest_height =
                *core_chips_and_heights.iter().map(|(_, height)| height).max().unwrap();
            let cpu_height =
                core_chips_and_heights.iter().find(|(name, _)| *name == cpu_name).unwrap().1;

            if biggest_height != cpu_height {
                return false;
            }

            let num_airs_at_cpu_height =
                core_chips_and_heights.iter().filter(|(_, height)| *height == cpu_height).count();

            num_airs_at_cpu_height <= 2
        };

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
            .chain(self.allowed_core_log_heights.iter().flat_map(
                move |(allowed_log_heights, filter)| {
                    Self::generate_all_shapes_from_allowed_log_heights({
                        let mut log_heights = allowed_log_heights
                            .iter()
                            .map(|(air, heights)| (air.name(), heights.clone()))
                            .collect::<HashMap<_, _>>();
                        log_heights.extend(preprocessed_heights.clone());
                        log_heights
                    })
                    .filter(move |shape| !filter || core_filter(shape))
                },
            ))
            .chain(Self::generate_all_shapes_from_allowed_log_heights(memory_heights))
            .chain(precompile_shapes)
    }
}

impl<F: PrimeField32> Default for CoreShapeConfig<F> {
    fn default() -> Self {
        let included_shapes = vec![];

        // Preprocessed chip heights.
        let program_heights = vec![Some(16), Some(19), Some(20), Some(21), Some(22)];
        let program_memory_heights = vec![Some(16), Some(19), Some(20), Some(21), Some(22)];

        let allowed_preprocessed_log_heights = HashMap::from([
            (RiscvAir::Program(ProgramChip::default()), program_heights),
            (RiscvAir::ProgramMemory(MemoryProgramChip::default()), program_memory_heights),
            (RiscvAir::ByteLookup(ByteChip::default()), vec![Some(16)]),
        ]);

        let mut allowed_core_log_heights = vec![];

        let small_cpu_heights = vec![16, 17, 18, 19, 20];

        for height in small_cpu_heights {
            // Get the heights for the short shape cluster (for small shards).
            let cpu_heights = vec![Some(height)];
            let divrem_heights = vec![None, Some(height)];
            let add_sub_heights = vec![None, Some(height)];
            let bitwise_heights = vec![None, Some(height)];
            let mul_heights = vec![None, Some(height)];
            let shift_right_heights = vec![None, Some(height)];
            let shift_left_heights = vec![None, Some(height)];
            let lt_heights = vec![None, Some(height)];
            let memory_local_heights = vec![Some(height)];
            let syscall_heights = vec![None, Some(height)];

            let short_allowed_log_heights = HashMap::from([
                (RiscvAir::Cpu(CpuChip::default()), cpu_heights),
                (RiscvAir::DivRem(DivRemChip::default()), divrem_heights),
                (RiscvAir::Add(AddSubChip::default()), add_sub_heights),
                (RiscvAir::Bitwise(BitwiseChip::default()), bitwise_heights),
                (RiscvAir::Mul(MulChip::default()), mul_heights),
                (RiscvAir::ShiftRight(ShiftRightChip::default()), shift_right_heights),
                (RiscvAir::ShiftLeft(ShiftLeft::default()), shift_left_heights),
                (RiscvAir::Lt(LtChip::default()), lt_heights),
                (RiscvAir::MemoryLocal(MemoryLocalChip::new()), memory_local_heights),
                (RiscvAir::SyscallCore(SyscallChip::core()), syscall_heights),
            ]);
            allowed_core_log_heights.push((short_allowed_log_heights, false));
        }

        // Get the heights for the medium shape cluster.
        let cpu_heights = vec![Some(21)];
        let divrem_heights = vec![None, Some(19), Some(20), Some(21)];
        let add_sub_heights = vec![None, Some(19), Some(20), Some(21)];
        let bitwise_heights = vec![None, Some(19), Some(20), Some(21)];
        let mul_heights = vec![None, Some(19), Some(20), Some(21)];
        let shift_right_heights = vec![None, Some(19), Some(20), Some(21)];
        let shift_left_heights = vec![None, Some(19), Some(20), Some(21)];
        let lt_heights = vec![None, Some(19), Some(20), Some(21)];
        let memory_local_heights = vec![Some(19), Some(20), Some(21)];
        let syscall_heights = vec![None, Some(19)];

        let medium_allowed_log_heights = HashMap::from([
            (RiscvAir::Cpu(CpuChip::default()), cpu_heights),
            (RiscvAir::DivRem(DivRemChip::default()), divrem_heights),
            (RiscvAir::Add(AddSubChip::default()), add_sub_heights),
            (RiscvAir::Bitwise(BitwiseChip::default()), bitwise_heights),
            (RiscvAir::Mul(MulChip::default()), mul_heights),
            (RiscvAir::ShiftRight(ShiftRightChip::default()), shift_right_heights),
            (RiscvAir::ShiftLeft(ShiftLeft::default()), shift_left_heights),
            (RiscvAir::Lt(LtChip::default()), lt_heights),
            (RiscvAir::MemoryLocal(MemoryLocalChip::new()), memory_local_heights),
            (RiscvAir::SyscallCore(SyscallChip::core()), syscall_heights),
        ]);

        allowed_core_log_heights.push((medium_allowed_log_heights, true));

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
        let precompile_heights = (1..19).collect::<Vec<_>>();
        for (air, mem_events_per_row) in RiscvAir::<F>::get_all_precompile_airs() {
            precompile_allowed_log_heights
                .insert(air, (mem_events_per_row, precompile_heights.clone()));
        }

        Self {
            included_shapes,
            allowed_preprocessed_log_heights,
            allowed_core_log_heights,
            memory_allowed_log_heights,
            precompile_allowed_log_heights,
        }
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;

    use super::*;

    #[test]
    #[ignore]
    fn test_making_shapes() {
        let shape_config = CoreShapeConfig::<BabyBear>::default();
        let num_shapes = shape_config.generate_all_allowed_shapes().count();
        println!("There are {} core shapes", num_shapes);
        assert!(num_shapes < 1 << 24);
    }
}
