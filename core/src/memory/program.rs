use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use p3_air::{Air, BaseAir, PairBuilder};
use p3_field::AbstractField;
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;

use sp1_derive::AlignedBorrow;

use crate::air::{AirInteraction, SP1AirBuilder};
use crate::air::{MachineAir, Word};
use crate::runtime::{ExecutionRecord, Program};
use crate::utils::pad_to_power_of_two;

pub const NUM_MEMORY_PROGRAM_PREPROCESSED_COLS: usize =
    size_of::<MemoryProgramPreprocessedCols<u8>>();
pub const NUM_MEMORY_PROGRAM_MULT_COLS: usize = size_of::<MemoryProgramMultCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct MemoryProgramPreprocessedCols<T> {
    pub addr: T,
    pub value: Word<T>,
}

/// The column layout for the chip.
#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct MemoryProgramMultCols<T> {
    pub used: T,
}

/// Chip that initializes memory that is provided from the program.
#[derive(Default)]
pub struct MemoryProgramChip;

impl MemoryProgramChip {
    pub fn new() -> Self {
        Self {}
    }
}

impl<F: PrimeField> MachineAir<F> for MemoryProgramChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "MemoryProgram".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_MEMORY_PROGRAM_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let program_memory = program.memory_image.clone();
        let rows = program_memory
            .into_iter()
            .enumerate()
            .map(|(i, (addr, word))| {
                let mut row = [F::zero(); NUM_MEMORY_PROGRAM_PREPROCESSED_COLS];
                let cols: &mut MemoryProgramPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                cols.addr = F::from_canonical_u32(addr);
                cols.value = Word::from(word);

                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEMORY_PROGRAM_PREPROCESSED_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_MEMORY_PROGRAM_PREPROCESSED_COLS, F>(&mut trace.values);

        Some(trace)
    }

    fn generate_dependencies(&self, _input: &ExecutionRecord, _output: &mut ExecutionRecord) {
        // Do nothing since this chip has no dependencies.
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.

        let rows = input
            .program_memory_events
            .iter()
            .enumerate()
            .map(|(i, event)| {
                let mut row = [F::zero(); NUM_MEMORY_PROGRAM_MULT_COLS];
                let cols: &mut MemoryProgramMultCols<F> = row.as_mut_slice().borrow_mut();
                cols.used = F::from_canonical_u32(event.used);
                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEMORY_PROGRAM_MULT_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_MEMORY_PROGRAM_MULT_COLS, F>(&mut trace.values);

        trace
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
    }
}

impl<F> BaseAir<F> for MemoryProgramChip {
    fn width(&self) -> usize {
        NUM_MEMORY_PROGRAM_MULT_COLS
    }
}

impl<AB> Air<AB> for MemoryProgramChip
where
    AB: SP1AirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let preprocessed = builder.preprocessed();

        let prep_local: &MemoryProgramPreprocessedCols<AB::Var> =
            preprocessed.row_slice(0).borrow();
        let mult_local: &MemoryProgramMultCols<AB::Var> = main.row_slice(0).borrow();

        builder.assert_bool(mult_local.used.clone());

        let mut values = vec![AB::Expr::zero(), AB::Expr::zero(), prep_local.addr.into()];
        values.extend(prep_local.value.map(Into::into));
        builder.receive(AirInteraction::new(
            values,
            mult_local.used.into(),
            crate::lookup::InteractionKind::Memory,
        ));
    }
}
