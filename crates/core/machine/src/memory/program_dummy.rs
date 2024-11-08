use core::mem::size_of;
use p3_air::{Air, AirBuilderWithPublicValues, BaseAir, PairBuilder};
use p3_matrix::dense::RowMajorMatrix;

use crate::memory::NUM_MEMORY_PROGRAM_PREPROCESSED_COLS;
use p3_field::PrimeField32;
use sp1_core_executor::{ExecutionRecord, Program};
use sp1_derive::AlignedBorrow;
use sp1_stark::air::{MachineAir, SP1AirBuilder};

use super::MemoryProgramChip;
use crate::utils::pad_rows_fixed;

pub const NUM_MEMORY_PROGRAM_DUMMY_MULT_COLS: usize = size_of::<MemoryProgramDummyMultCols<u8>>();

/// Multiplicity columns.
#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct MemoryProgramDummyMultCols<T> {
    /// A dummy column to prevent the main trace from being empty
    pub dummy: T,
}

/// `MemoryProgramDummyChip` is to be used in non-first shards in place of `MemoryProgramChip`.
/// This allows all the shards to share the same preprocessed trace, but the dummy version has less columns due to not having global interactions.
/// [TODO]: Add the condition that the first shard must have `MemoryProgramChip` inside recursive verifier.
/// [TODO]: Make the shape selection logic to be dependent on the shard number.
#[derive(Default)]
pub struct MemoryProgramDummyChip;

impl MemoryProgramDummyChip {
    pub const fn new() -> Self {
        Self {}
    }
}

impl<F: PrimeField32> MachineAir<F> for MemoryProgramDummyChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "MemoryProgramDummy".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_MEMORY_PROGRAM_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        MemoryProgramChip::new().generate_preprocessed_trace(program)
    }

    fn generate_dependencies(&self, _input: &ExecutionRecord, _output: &mut ExecutionRecord) {
        // This is a no-op.
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        // Pad the trace to a power of two depending on the proof shape in `input`.
        pad_rows_fixed(
            &mut rows,
            || [F::zero(); NUM_MEMORY_PROGRAM_DUMMY_MULT_COLS],
            input.fixed_log2_rows::<F, _>(self),
        );

        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEMORY_PROGRAM_DUMMY_MULT_COLS,
        )
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
    }
}

impl<F> BaseAir<F> for MemoryProgramDummyChip {
    fn width(&self) -> usize {
        NUM_MEMORY_PROGRAM_DUMMY_MULT_COLS
    }
}

impl<AB> Air<AB> for MemoryProgramDummyChip
where
    AB: SP1AirBuilder + PairBuilder + AirBuilderWithPublicValues,
{
    fn eval(&self, _builder: &mut AB) {}
}
