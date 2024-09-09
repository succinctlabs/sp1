use core::panic;
use std::iter::once;

use itertools::Itertools;

use hashbrown::HashMap;
use p3_field::PrimeField32;
use sp1_core_executor::{CoreShape, ExecutionRecord, Program};
use sp1_stark::{air::MachineAir, ProofShape};
use thiserror::Error;

use crate::memory::MemoryProgramChip;

use super::{
    AddSubChip, BitwiseChip, CpuChip, DivRemChip, LtChip, MulChip, ProgramChip, RiscvAir,
    ShiftLeft, ShiftRightChip,
};

const MAX_PRECOMPILE_LOG_HEIGHT: usize = 20;

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
    allowed_preprocessed_log_heights: HashMap<RiscvAir<F>, Vec<usize>>,
    short_allowed_log_heights: HashMap<RiscvAir<F>, Vec<usize>>,
    long_allowed_log_heights: HashMap<RiscvAir<F>, Vec<usize>>,
    max_precompile_log_height: usize,
}

impl<F: PrimeField32> CoreShapeConfig<F> {
    /// Fix the preprocessed shape of the proof.
    pub fn fix_preprocessed_shape(&self, program: &mut Program) -> Result<(), CoreShapeError> {
        if program.preprocessed_shape.is_some() {
            tracing::warn!("preprocessed shape already fixed");
            // TODO: Change this to not panic (i.e. return);
            panic!("cannot fix preprocessed shape twice");
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
        allowed_log_heights: &HashMap<RiscvAir<F>, Vec<usize>>,
    ) -> Option<CoreShape> {
        let shape: Option<HashMap<String, usize>> = heights
            .iter()
            .map(|(air, height)| {
                for &allowed_log_height in allowed_log_heights.get(air).unwrap() {
                    let allowed_height = 1 << allowed_log_height;
                    if *height <= allowed_height {
                        return Some((air.name(), allowed_log_height));
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

        // Get the heights of the core airs in the record.
        let heights = RiscvAir::<F>::core_heights(record);

        // Try to find a shape within the included shapes.

        // Try to find a shape within the short shape cluster.
        if let Some(shape) =
            Self::find_shape_with_allowed_heights(&heights, &self.short_allowed_log_heights)
        {
            record.shape = Some(shape);
            return Ok(());
        }
        // Try to find a shape within the long shape cluster.
        if let Some(shape) =
            Self::find_shape_with_allowed_heights(&heights, &self.long_allowed_log_heights)
        {
            record.shape = Some(shape);
            return Ok(());
        }

        // No shape found, so return an error.
        Err(CoreShapeError::ShapeError)
    }

    fn generate_all_shapes_from_allowed_log_heights(
        allowed_log_heights: &HashMap<RiscvAir<F>, Vec<usize>>,
    ) -> impl Iterator<Item = ProofShape> + '_ {
        // for chip in allowed_heights.
        allowed_log_heights
            .iter()
            .map(|(chip, heights)| {
                let name = chip.name();
                once((name.clone(), None))
                    .chain(heights.iter().map(move |height| (name.clone(), Some(*height))))
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
                &self.short_allowed_log_heights,
            ))
            .chain(Self::generate_all_shapes_from_allowed_log_heights(
                &self.long_allowed_log_heights,
            ))
    }
}

impl<F: PrimeField32> Default for CoreShapeConfig<F> {
    fn default() -> Self {
        let included_shapes = vec![];

        // Preprocessed chip heights.
        let program_heights = vec![10, 16, 20, 21, 22];
        let program_memory_heights = vec![10, 16, 20, 21, 22];

        let allowed_preprocessed_log_heights = HashMap::from([
            (RiscvAir::Program(ProgramChip::default()), program_heights.clone()),
            (RiscvAir::ProgramMemory(MemoryProgramChip::default()), program_memory_heights.clone()),
        ]);

        // Get the heights for the short shape cluster.
        let cpu_heights = vec![20, 21];
        let divrem_heights = vec![19, 20, 21];
        let add_sub_heights = vec![19, 20, 21];
        let bitwise_heights = vec![19, 20, 21];
        let mul_heights = vec![19, 20, 21];
        let shift_right_heights = vec![19, 20, 21];
        let shift_left_heights = vec![19, 20, 21];
        let lt_heights = vec![19, 20, 21];

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
        let cpu_heights = vec![21, 22];
        let divrem_heights = vec![21, 22];
        let add_sub_heights = vec![21, 22];
        let bitwise_heights = vec![21, 22];
        let mul_heights = vec![21, 22];
        let shift_right_heights = vec![21, 22];
        let shift_left_heights = vec![21, 22];
        let lt_heights = vec![21, 22];

        let mut long_allowed_log_heights = HashMap::from([
            (RiscvAir::Program(ProgramChip::default()), program_heights),
            (RiscvAir::ProgramMemory(MemoryProgramChip::default()), program_memory_heights),
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

        Self {
            included_shapes,
            allowed_preprocessed_log_heights,
            short_allowed_log_heights,
            long_allowed_log_heights,
            max_precompile_log_height: MAX_PRECOMPILE_LOG_HEIGHT,
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
