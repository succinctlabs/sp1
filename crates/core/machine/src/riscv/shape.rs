use itertools::Itertools;

use hashbrown::{HashMap, HashSet};
use p3_field::PrimeField32;
use sp1_core_executor::{CoreShape, ExecutionRecord, Program};
use sp1_stark::{air::MachineAir, ProofShape};
use thiserror::Error;

use crate::{
    memory::MemoryProgramChip,
    riscv::MemoryChipType::{Finalize, Initialize},
};

use super::{
    AddSubChip, BitwiseChip, CpuChip, DivRemChip, LtChip, MemoryGlobalChip, MulChip, ProgramChip,
    RiscvAir, ShiftLeft, ShiftRightChip,
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
    short_core_allowed_log_heights: HashMap<RiscvAir<F>, Vec<Option<usize>>>,
    medium_core_allowed_log_heights: HashMap<RiscvAir<F>, Vec<Option<usize>>>,
    long_core_allowed_log_heights: HashMap<RiscvAir<F>, Vec<Option<usize>>>,
    memory_allowed_log_heights: HashMap<RiscvAir<F>, Vec<Option<usize>>>,
    precompile_allowed_log_heights: Vec<HashMap<RiscvAir<F>, Vec<Option<usize>>>>,
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

            // Try to find a shape within the short shape cluster.
            if let Some(shape) = Self::find_shape_from_allowed_heights(
                &heights,
                &self.short_core_allowed_log_heights,
            ) {
                record.shape.as_mut().unwrap().extend(shape);
                return Ok(());
            }

            // Try to find a shape within the medium shape cluster.
            if let Some(shape) = Self::find_shape_from_allowed_heights(
                &heights,
                &self.medium_core_allowed_log_heights,
            ) {
                record.shape.as_mut().unwrap().extend(shape);
                return Ok(());
            }

            // Try to find a shape within the long shape cluster.
            if let Some(shape) =
                Self::find_shape_from_allowed_heights(&heights, &self.long_core_allowed_log_heights)
            {
                record.shape.as_mut().unwrap().extend(shape);
                return Ok(());
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

        // Otherwise, try to fix the shape as a precompile record. Since we allow all possible
        // heights up to 1 << 22, we currently just don't fix the shape, but making sure the shape
        // is included
        self.precompile_allowed_log_heights
            .iter()
            .find_map(|allowed_log_heights| {
                // Check if the precompile is included in the shapes.
                for (air, _) in allowed_log_heights {
                    if !air.included(record) {
                        return None;
                    }
                }
                Some(())
            })
            .ok_or(CoreShapeError::PrecompileNotIncluded)?;
        Ok(())
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

        let mut short_heights = self
            .short_core_allowed_log_heights
            .iter()
            .map(|(air, heights)| (air.name(), heights.clone()))
            .collect::<HashMap<_, _>>();
        short_heights.extend(preprocessed_heights.clone());

        let mut medium_heights = self
            .medium_core_allowed_log_heights
            .iter()
            .map(|(air, heights)| (air.name(), heights.clone()))
            .collect::<HashMap<_, _>>();
        medium_heights.extend(preprocessed_heights.clone());

        let mut long_heights = self
            .long_core_allowed_log_heights
            .iter()
            .map(|(air, heights)| (air.name(), heights.clone()))
            .collect::<HashMap<_, _>>();
        long_heights.extend(preprocessed_heights.clone());

        let mut memory_heights = self
            .memory_allowed_log_heights
            .iter()
            .map(|(air, heights)| (air.name(), heights.clone()))
            .collect::<HashMap<_, _>>();
        memory_heights.extend(preprocessed_heights.clone());

        let precompile_heights = self
            .precompile_allowed_log_heights
            .iter()
            .map(|allowed_log_heights| {
                let mut heights = allowed_log_heights
                    .iter()
                    .map(|(air, heights)| (air.name(), heights.clone()))
                    .collect::<HashMap<_, _>>();
                heights.extend(preprocessed_heights.clone());
                heights
            })
            .collect::<Vec<_>>();

        let included_shapes =
            self.included_shapes.iter().map(ProofShape::from_map).collect::<Vec<_>>();

        let cpu_name = || RiscvAir::<F>::Cpu(CpuChip::default()).name();
        let core_filter = move |shape: &ProofShape| {
            let core_airs = RiscvAir::<F>::get_all_core_airs()
                .into_iter()
                .map(|air| air.name())
                .collect::<HashSet<_>>();
            let core_chips_and_heights = shape
                .chip_information
                .iter()
                .filter(|(name, _)| core_airs.contains(name))
                .cloned()
                .collect::<Vec<_>>();

            let cpu_name = cpu_name();

            if core_chips_and_heights.first().unwrap().0 != cpu_name {
                return false;
            }

            let cpu_height = core_chips_and_heights.first().unwrap().1;
            let num_core_chips_at_cpu_height =
                core_chips_and_heights.iter().filter(|(_, height)| *height == cpu_height).count();

            if num_core_chips_at_cpu_height > 2 {
                return false;
            }

            let sum_of_heights =
                core_chips_and_heights.iter().map(|(_, height)| *height).sum::<usize>();

            let mut max_possible_sum_of_heights = cpu_height;

            let num_core_chips = core_chips_and_heights.len();

            if num_core_chips > 1 {
                max_possible_sum_of_heights =
                    2 * cpu_height + (cpu_height >> 1) * (num_core_chips - 2);
            }

            sum_of_heights <= max_possible_sum_of_heights
        };

        included_shapes
            .into_iter()
            .chain(
                Self::generate_all_shapes_from_allowed_log_heights(short_heights)
                    .filter(core_filter),
            )
            .chain(
                Self::generate_all_shapes_from_allowed_log_heights(medium_heights)
                    .filter(core_filter),
            )
            .chain(
                Self::generate_all_shapes_from_allowed_log_heights(long_heights)
                    .filter(core_filter),
            )
            .chain(Self::generate_all_shapes_from_allowed_log_heights(memory_heights))
            .chain(precompile_heights.into_iter().flat_map(|allowed_log_heights| {
                Self::generate_all_shapes_from_allowed_log_heights(allowed_log_heights)
            }))
    }
}

impl<F: PrimeField32> Default for CoreShapeConfig<F> {
    fn default() -> Self {
        let included_shapes = vec![];

        // Preprocessed chip heights.
        let program_heights = vec![Some(16), Some(20), Some(21), Some(22)];
        let program_memory_heights = vec![Some(16), Some(20), Some(21), Some(22)];

        let allowed_preprocessed_log_heights = HashMap::from([
            (RiscvAir::Program(ProgramChip::default()), program_heights),
            (RiscvAir::ProgramMemory(MemoryProgramChip::default()), program_memory_heights),
        ]);

        // Get the heights for the short shape cluster (for small shards).
        let cpu_heights = vec![Some(10), Some(16)];
        let divrem_heights = vec![None, Some(10), Some(16)];
        let add_sub_heights = vec![None, Some(10), Some(16)];
        let bitwise_heights = vec![None, Some(10), Some(16)];
        let mul_heights = vec![None, Some(10), Some(16)];
        let shift_right_heights = vec![None, Some(10), Some(16)];
        let shift_left_heights = vec![None, Some(10), Some(16)];
        let lt_heights = vec![None, Some(10), Some(16)];

        let short_allowed_log_heights = HashMap::from([
            (RiscvAir::Cpu(CpuChip::default()), cpu_heights),
            (RiscvAir::DivRem(DivRemChip::default()), divrem_heights),
            (RiscvAir::Add(AddSubChip::default()), add_sub_heights),
            (RiscvAir::Bitwise(BitwiseChip::default()), bitwise_heights),
            (RiscvAir::Mul(MulChip::default()), mul_heights),
            (RiscvAir::ShiftRight(ShiftRightChip::default()), shift_right_heights),
            (RiscvAir::ShiftLeft(ShiftLeft::default()), shift_left_heights),
            (RiscvAir::Lt(LtChip::default()), lt_heights),
        ]);

        // Get the heights for the medium shape cluster.
        let cpu_heights = vec![Some(20), Some(21)];
        let divrem_heights = vec![None, Some(19), Some(20), Some(21)];
        let add_sub_heights = vec![None, Some(19), Some(20), Some(21)];
        let bitwise_heights = vec![None, Some(19), Some(20), Some(21)];
        let mul_heights = vec![None, Some(19), Some(20), Some(21)];
        let shift_right_heights = vec![None, Some(19), Some(20), Some(21)];
        let shift_left_heights = vec![None, Some(19), Some(20), Some(21)];
        let lt_heights = vec![None, Some(19), Some(20), Some(21)];

        let medium_allowed_log_heights = HashMap::from([
            (RiscvAir::Cpu(CpuChip::default()), cpu_heights),
            (RiscvAir::DivRem(DivRemChip::default()), divrem_heights),
            (RiscvAir::Add(AddSubChip::default()), add_sub_heights),
            (RiscvAir::Bitwise(BitwiseChip::default()), bitwise_heights),
            (RiscvAir::Mul(MulChip::default()), mul_heights),
            (RiscvAir::ShiftRight(ShiftRightChip::default()), shift_right_heights),
            (RiscvAir::ShiftLeft(ShiftLeft::default()), shift_left_heights),
            (RiscvAir::Lt(LtChip::default()), lt_heights),
        ]);

        // Core chip heights for the long shape cluster.
        let cpu_heights = vec![Some(21), Some(22)];
        let divrem_heights = vec![None, Some(20), Some(21), Some(22)];
        let add_sub_heights = vec![None, Some(20), Some(21), Some(22)];
        let bitwise_heights = vec![None, Some(20), Some(21), Some(22)];
        let mul_heights = vec![None, Some(20), Some(21), Some(22)];
        let shift_right_heights = vec![None, Some(20), Some(21), Some(22)];
        let shift_left_heights = vec![None, Some(20), Some(21), Some(22)];
        let lt_heights = vec![None, Some(20), Some(21), Some(22)];

        let long_allowed_log_heights = HashMap::from([
            (RiscvAir::Cpu(CpuChip::default()), cpu_heights),
            (RiscvAir::DivRem(DivRemChip::default()), divrem_heights),
            (RiscvAir::Add(AddSubChip::default()), add_sub_heights),
            (RiscvAir::Bitwise(BitwiseChip::default()), bitwise_heights),
            (RiscvAir::Mul(MulChip::default()), mul_heights),
            (RiscvAir::ShiftRight(ShiftRightChip::default()), shift_right_heights),
            (RiscvAir::ShiftLeft(ShiftLeft::default()), shift_left_heights),
            (RiscvAir::Lt(LtChip::default()), lt_heights),
        ]);

        // Set the memory init and finalize heights.
        let memory_init_heights =
            vec![Some(10), Some(16), Some(18), Some(19), Some(20), Some(21), Some(22)];
        let memory_finalize_heights =
            vec![Some(10), Some(16), Some(18), Some(19), Some(20), Some(21), Some(22)];
        let memory_allowed_log_heights = HashMap::from([
            (RiscvAir::MemoryGlobalInit(MemoryGlobalChip::new(Initialize)), memory_init_heights),
            (RiscvAir::MemoryGlobalFinal(MemoryGlobalChip::new(Finalize)), memory_finalize_heights),
        ]);

        let mut precompile_allowed_log_heights: Vec<HashMap<_, _>> = vec![];
        let precompile_heights = (1..22).map(Some).collect::<Vec<_>>();
        for air in RiscvAir::<F>::get_all_precompile_airs() {
            let allowed_log_heights = HashMap::from([(air, precompile_heights.clone())]);
            precompile_allowed_log_heights.push(allowed_log_heights);
        }

        Self {
            included_shapes,
            allowed_preprocessed_log_heights,
            short_core_allowed_log_heights: short_allowed_log_heights,
            medium_core_allowed_log_heights: medium_allowed_log_heights,
            long_core_allowed_log_heights: long_allowed_log_heights,
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
