use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use p3_air::{Air, BaseAir, PairBuilder};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use sp1_core::air::{AirInteraction, MachineAir, SP1AirBuilder};
use sp1_core::lookup::InteractionKind;
use sp1_core::utils::pad_to_power_of_two;
use std::collections::HashMap;

use sp1_derive::AlignedBorrow;

use crate::cpu::columns::InstructionCols;
use crate::cpu::columns::OpcodeSelectorCols;
use crate::runtime::{ExecutionRecord, Program};

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
    pub fn new() -> Self {
        Self {}
    }
}

impl<F: PrimeField32> MachineAir<F> for ProgramChip {
    type Record = ExecutionRecord<F>;

    type Program = Program<F>;

    fn name(&self) -> String {
        "Program".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PROGRAM_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let rows = program
            .instructions
            .clone()
            .into_iter()
            .enumerate()
            .map(|(i, instruction)| {
                let pc = i as u32 * 4;
                let mut row = [F::zero(); NUM_PROGRAM_PREPROCESSED_COLS];
                let cols: &mut ProgramPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                cols.pc = F::from_canonical_u32(pc);
                cols.selectors.populate(&instruction);
                cols.instruction.populate(instruction);

                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_PROGRAM_PREPROCESSED_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_PROGRAM_PREPROCESSED_COLS, F>(&mut trace.values);

        Some(trace)
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _output: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.

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

        let rows = input
            .program
            .instructions
            .clone()
            .into_iter()
            .enumerate()
            .map(|(i, _)| {
                let pc = i as u32 * 4;
                let mut row = [F::zero(); NUM_PROGRAM_MULT_COLS];
                let cols: &mut ProgramMultiplicityCols<F> = row.as_mut_slice().borrow_mut();
                cols.multiplicity =
                    F::from_canonical_usize(*instruction_counts.get(&pc).unwrap_or(&0));
                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_PROGRAM_MULT_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_PROGRAM_MULT_COLS, F>(&mut trace.values);

        trace
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
    AB: SP1AirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let preprocessed = builder.preprocessed();

        let prep_local: &ProgramPreprocessedCols<AB::Var> = preprocessed.row_slice(0).borrow();
        let mult_local: &ProgramMultiplicityCols<AB::Var> = main.row_slice(0).borrow();

        // Dummy constraint of degree 3.
        builder.assert_eq(
            prep_local.pc * prep_local.pc * prep_local.pc,
            prep_local.pc * prep_local.pc * prep_local.pc,
        );

        let mut interaction_vals: Vec<AB::Expr> = vec![prep_local.instruction.opcode.into()];
        interaction_vals.push(prep_local.instruction.op_a.into());
        interaction_vals.extend_from_slice(&prep_local.instruction.op_b.map(|x| x.into()).0);
        interaction_vals.extend_from_slice(&prep_local.instruction.op_c.map(|x| x.into()).0);
        interaction_vals.push(prep_local.instruction.imm_b.into());
        interaction_vals.push(prep_local.instruction.imm_c.into());
        builder.receive(AirInteraction::new(
            interaction_vals,
            mult_local.multiplicity.into(),
            InteractionKind::Program,
        ));
    }
}
