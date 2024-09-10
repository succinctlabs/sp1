use itertools::Itertools;

use hashbrown::HashMap;
use p3_field::PrimeField32;
use sp1_core_executor::{CoreShape, ExecutionRecord, Program};
use sp1_stark::{air::MachineAir, ProofShape};
use thiserror::Error;

use crate::memory::{MemoryChipType, MemoryProgramChip};

use super::{
    AddSubChip, BitwiseChip, CpuChip, DivRemChip, LtChip, MemoryChip, MulChip, ProgramChip,
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
}

/// A structure that enables fixing the shape of an executionrecord.
pub struct CoreShapeConfig<F: PrimeField32> {
    included_shapes: Vec<HashMap<String, usize>>,
    allowed_preprocessed_log_heights: HashMap<RiscvAir<F>, Vec<Option<usize>>>,
    short_core_allowed_log_heights: HashMap<RiscvAir<F>, Vec<Option<usize>>>,
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
            Self::find_shape_with_allowed_heights(&heights, &self.allowed_preprocessed_log_heights)
                .ok_or(CoreShapeError::PreprocessedShapeError)?;

        program.preprocessed_shape = Some(prep_shape);
        Ok(())
    }

    #[inline]
    fn find_shape_with_allowed_heights(
        heights: &[(RiscvAir<F>, usize)],
        allowed_log_heights: &HashMap<RiscvAir<F>, Vec<Option<usize>>>,
    ) -> Option<CoreShape> {
        let shape: Option<HashMap<String, usize>> = heights
            .iter()
            .map(|(air, height)| {
                for allowed_log_height in allowed_log_heights.get(air).unwrap().iter().flatten() {
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

        // If cpu is not included, try to fix the shape as a precompile.
        if record.cpu_events.is_empty() {
            // If this is a memory init/finalize shard, try to fix the shape.
        }

        // If cpu is included, try to fix the shape as a core.

        // Get the heights of the core airs in the record.
        let heights = RiscvAir::<F>::core_heights(record);

        // Try to find a shape within the included shapes.

        // Try to find a shape within the short shape cluster.
        if let Some(shape) =
            Self::find_shape_with_allowed_heights(&heights, &self.short_core_allowed_log_heights)
        {
            record.shape = Some(shape);
            return Ok(());
        }
        // Try to find a shape within the long shape cluster.
        if let Some(shape) =
            Self::find_shape_with_allowed_heights(&heights, &self.long_core_allowed_log_heights)
        {
            record.shape = Some(shape);
            return Ok(());
        }

        // No shape found, so return an error.
        Err(CoreShapeError::ShapeError)
    }

    fn generate_all_shapes_from_allowed_log_heights(
        allowed_log_heights: &HashMap<RiscvAir<F>, Vec<Option<usize>>>,
    ) -> impl Iterator<Item = ProofShape> + '_ {
        // for chip in allowed_heights.
        allowed_log_heights
            .iter()
            .map(|(chip, heights)| {
                let name = chip.name();
                heights.iter().map(move |height| (name.clone(), *height))
            })
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
        self.included_shapes
            .iter()
            .map(ProofShape::from_map)
            .chain(Self::generate_all_shapes_from_allowed_log_heights(
                &self.short_core_allowed_log_heights,
            ))
            .chain(Self::generate_all_shapes_from_allowed_log_heights(
                &self.long_core_allowed_log_heights,
            ))
            .chain(Self::generate_all_shapes_from_allowed_log_heights(
                &self.memory_allowed_log_heights,
            ))
            .chain(self.precompile_allowed_log_heights.iter().flat_map(|allowed_log_heights| {
                Self::generate_all_shapes_from_allowed_log_heights(allowed_log_heights)
            }))
    }
}

impl<F: PrimeField32> Default for CoreShapeConfig<F> {
    fn default() -> Self {
        let included_shapes = vec![];

        // Preprocessed chip heights.
        let program_heights = vec![Some(10), Some(16), Some(20), Some(21), Some(22)];
        let program_memory_heights = vec![Some(10), Some(16), Some(20), Some(21), Some(22)];

        let allowed_preprocessed_log_heights = HashMap::from([
            (RiscvAir::Program(ProgramChip::default()), program_heights.clone()),
            (RiscvAir::ProgramMemory(MemoryProgramChip::default()), program_memory_heights.clone()),
        ]);

        // Get the heights for the short shape cluster.
        let cpu_heights = vec![Some(20), Some(21)];
        let divrem_heights = vec![None, Some(19), Some(20), Some(21)];
        let add_sub_heights = vec![None, Some(19), Some(20), Some(21)];
        let bitwise_heights = vec![None, Some(19), Some(20), Some(21)];
        let mul_heights = vec![None, Some(19), Some(20), Some(21)];
        let shift_right_heights = vec![None, Some(19), Some(20), Some(21)];
        let shift_left_heights = vec![None, Some(19), Some(20), Some(21)];
        let lt_heights = vec![None, Some(19), Some(20), Some(21)];

        let mut short_allowed_log_heights = HashMap::from([
            (RiscvAir::Program(ProgramChip::default()), program_heights.clone()),
            (RiscvAir::ProgramMemory(MemoryProgramChip::default()), program_memory_heights.clone()),
        ]);
        short_allowed_log_heights.extend([
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
        let divrem_heights = vec![None, Some(21), Some(22)];
        let add_sub_heights = vec![None, Some(21), Some(22)];
        let bitwise_heights = vec![None, Some(21), Some(22)];
        let mul_heights = vec![None, Some(21), Some(22)];
        let shift_right_heights = vec![None, Some(21), Some(22)];
        let shift_left_heights = vec![None, Some(21), Some(22)];
        let lt_heights = vec![None, Some(21), Some(22)];

        let mut long_allowed_log_heights = HashMap::from([
            (RiscvAir::Program(ProgramChip::default()), program_heights.clone()),
            (RiscvAir::ProgramMemory(MemoryProgramChip::default()), program_memory_heights.clone()),
        ]);
        long_allowed_log_heights.extend([
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
        let mut memory_allowed_log_heights = HashMap::from([
            (RiscvAir::Program(ProgramChip::default()), program_heights.clone()),
            (RiscvAir::ProgramMemory(MemoryProgramChip::default()), program_memory_heights.clone()),
        ]);
        memory_allowed_log_heights.extend([
            (
                RiscvAir::MemoryInit(MemoryChip::new(MemoryChipType::Initialize)),
                memory_init_heights,
            ),
            (
                RiscvAir::MemoryFinal(MemoryChip::new(MemoryChipType::Finalize)),
                memory_finalize_heights,
            ),
        ]);

        let mut precompile_allowed_log_heights: Vec<HashMap<_, _>> = vec![];
        let precompile_heights = vec![Some(10), Some(16), Some(20), Some(21), Some(22)];
        for air in RiscvAir::<F>::get_all_precompile_airs() {
            let mut allowed_log_heights = HashMap::from([
                (RiscvAir::Program(ProgramChip::default()), program_heights.clone()),
                (
                    RiscvAir::ProgramMemory(MemoryProgramChip::default()),
                    program_memory_heights.clone(),
                ),
            ]);
            allowed_log_heights.insert(air, precompile_heights.clone());
            precompile_allowed_log_heights.push(allowed_log_heights);
        }

        Self {
            included_shapes,
            allowed_preprocessed_log_heights,
            short_core_allowed_log_heights: short_allowed_log_heights,
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
