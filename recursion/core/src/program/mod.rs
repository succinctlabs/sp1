use crate::{cpu::columns::InstructionCols, runtime::ExecutionRecord};
use core::mem::size_of;
use p3_air::{Air, BaseAir};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use sp1_core::lookup::InteractionKind;
use sp1_core::{
    air::{AirInteraction, MachineAir, SP1AirBuilder},
    utils::pad_to_power_of_two,
};
use sp1_derive::AlignedBorrow;
use std::borrow::Borrow;
use std::borrow::BorrowMut;
use std::collections::HashMap;

pub const NUM_PROGRAM_COLS: usize = size_of::<ProgramCols<u8>>();

#[derive(Default)]
pub struct ProgramChip;

#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct ProgramCols<T> {
    pub pc: T,
    pub instruction: InstructionCols<T>,
    pub multiplicity: T,
}

impl<F: PrimeField32> MachineAir<F> for ProgramChip {
    type Record = ExecutionRecord<F>;

    fn name(&self) -> String {
        "Program".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _output: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let mut instruction_counts = HashMap::new();
        input.cpu_events.iter().for_each(|event| {
            let pc = event.pc;
            instruction_counts
                .entry(pc)
                .and_modify(|count| *count += 1)
                .or_insert(1);
        });
        let rows = input
            .program
            .instructions
            .clone()
            .into_iter()
            .enumerate()
            .map(|(i, instruction)| {
                let pc = F::from_canonical_u32(i as u32);
                let mut row = [F::zero(); NUM_PROGRAM_COLS];
                let cols: &mut ProgramCols<F> = row.as_mut_slice().borrow_mut();
                cols.pc = pc;
                cols.instruction.opcode = F::from_canonical_u32(instruction.opcode as u32);
                cols.instruction.op_a = instruction.op_a;
                cols.instruction.op_b = instruction.op_b;
                cols.instruction.op_c = instruction.op_c;
                cols.instruction.imm_b = F::from_bool(instruction.imm_b);
                cols.instruction.imm_c = F::from_bool(instruction.imm_c);
                cols.multiplicity =
                    F::from_canonical_usize(*instruction_counts.get(&cols.pc).unwrap_or(&0));
                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_PROGRAM_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_PROGRAM_COLS, F>(&mut trace.values);

        trace
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
    }
}

impl<F> BaseAir<F> for ProgramChip {
    fn width(&self) -> usize {
        NUM_PROGRAM_COLS
    }
}

impl<AB> Air<AB> for ProgramChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &ProgramCols<AB::Var> = main.row_slice(0).borrow();

        // Dummy constraint of degree 3.
        builder.assert_eq(
            local.pc * local.pc * local.pc,
            local.pc * local.pc * local.pc,
        );

        let mut interaction_vals: Vec<AB::Expr> = vec![local.instruction.opcode.into()];
        interaction_vals.push(local.instruction.op_a.into());
        interaction_vals.extend_from_slice(&local.instruction.op_b.map(|x| x.into()).0);
        interaction_vals.extend_from_slice(&local.instruction.op_c.map(|x| x.into()).0);
        interaction_vals.push(local.instruction.imm_b.into());
        interaction_vals.push(local.instruction.imm_c.into());
        builder.receive(AirInteraction::new(
            interaction_vals,
            local.multiplicity.into(),
            InteractionKind::Program,
        ));
    }
}
