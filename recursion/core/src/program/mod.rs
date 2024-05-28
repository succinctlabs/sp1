use crate::air::SP1RecursionAirBuilder;
use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use p3_air::{Air, BaseAir, PairBuilder};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_core::air::MachineAir;
use sp1_core::utils::pad_rows_fixed;
use std::collections::HashMap;
use tracing::instrument;

use sp1_derive::AlignedBorrow;

use crate::cpu::columns::InstructionCols;
use crate::cpu::columns::OpcodeSelectorCols;
use crate::runtime::{ExecutionRecord, RecursionProgram};

pub const NUM_PROGRAM_PREPROCESSED_COLS: usize = size_of::<ProgramPreprocessedCols<u8>>();
pub const NUM_PROGRAM_MULT_COLS: usize = size_of::<ProgramMultiplicityCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct ProgramPreprocessedCols<T> {
    pub pc: T,
    pub instruction: InstructionCols<T>,
    pub selectors: OpcodeSelectorCols<T>,
}

/// The column layout for the chip.
#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct ProgramMultiplicityCols<T> {
    pub multiplicity: T,
}

/// A chip that implements addition for the opcodes ADD and ADDI.
#[derive(Default)]
pub struct ProgramChip;

impl ProgramChip {
    pub const fn new() -> Self {
        Self {}
    }
}

impl<F: PrimeField32> MachineAir<F> for ProgramChip {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "Program".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PROGRAM_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let max_program_size = match std::env::var("MAX_RECURSION_PROGRAM_SIZE") {
            Ok(value) => value.parse().unwrap(),
            Err(_) => std::cmp::min(1048576, program.instructions.len()),
        };
        let mut rows = program.instructions[0..max_program_size]
            .iter()
            .enumerate()
            .map(|(i, instruction)| {
                let pc = i as u32;
                let mut row = [F::zero(); NUM_PROGRAM_PREPROCESSED_COLS];
                let cols: &mut ProgramPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                cols.pc = F::from_canonical_u32(pc);
                cols.selectors.populate(instruction);
                cols.instruction.populate(instruction);
                row
            })
            .collect::<Vec<_>>();

        // Pad the trace to a power of two.
        pad_rows_fixed(
            &mut rows,
            || [F::zero(); NUM_PROGRAM_PREPROCESSED_COLS],
            None,
        );

        // Convert the trace to a row major matrix.
        Some(RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_PROGRAM_PREPROCESSED_COLS,
        ))
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    #[instrument(name = "generate program trace", level = "debug", skip_all, fields(rows = input.program.instructions.len()))]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _output: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        // Collect the number of times each instruction is called from the cpu events.
        // Store it as a map of PC -> count.
        let mut instruction_counts = HashMap::new();
        input.cpu_events.iter().for_each(|event| {
            let pc = event.pc;
            instruction_counts
                .entry(pc.as_canonical_u32())
                .and_modify(|count| *count += 1)
                .or_insert(1);
        });

        let max_program_size = match std::env::var("MAX_RECURSION_PROGRAM_SIZE") {
            Ok(value) => value.parse().unwrap(),
            Err(_) => std::cmp::min(1048576, input.program.instructions.len()),
        };
        let mut rows = input.program.instructions[0..max_program_size]
            .iter()
            .enumerate()
            .map(|(i, _)| {
                let pc = i as u32;
                let mut row = [F::zero(); NUM_PROGRAM_MULT_COLS];
                let cols: &mut ProgramMultiplicityCols<F> = row.as_mut_slice().borrow_mut();
                cols.multiplicity =
                    F::from_canonical_usize(*instruction_counts.get(&pc).unwrap_or(&0));
                row
            })
            .collect::<Vec<_>>();

        // Pad the trace to a power of two.
        pad_rows_fixed(&mut rows, || [F::zero(); NUM_PROGRAM_MULT_COLS], None);

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_PROGRAM_MULT_COLS,
        )
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
    }
}

impl<F> BaseAir<F> for ProgramChip {
    fn width(&self) -> usize {
        NUM_PROGRAM_MULT_COLS
    }
}

impl<AB> Air<AB> for ProgramChip
where
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let preprocessed = builder.preprocessed();

        let prep_local = preprocessed.row_slice(0);
        let prep_local: &ProgramPreprocessedCols<AB::Var> = (*prep_local).borrow();
        let mult_local = main.row_slice(0);
        let mult_local: &ProgramMultiplicityCols<AB::Var> = (*mult_local).borrow();

        builder.receive_program(
            prep_local.pc,
            prep_local.instruction,
            prep_local.selectors,
            mult_local.multiplicity,
        );
    }
}
