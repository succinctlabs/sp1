use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use p3_air::{Air, BaseAir};
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use std::collections::HashMap;

use valida_derive::AlignedBorrow;

use crate::air::CurtaAirBuilder;
use crate::cpu::columns::instruction::InstructionCols;
use crate::cpu::columns::opcode::OpcodeSelectorCols;
use crate::runtime::Segment;
use crate::utils::{pad_to_power_of_two, Chip};

pub const NUM_PROGRAM_COLS: usize = size_of::<ProgramCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct ProgramCols<T> {
    pub pc: T,
    pub instruction: InstructionCols<T>,
    pub selectors: OpcodeSelectorCols<T>,
    pub multiplicity: T,
}

/// A chip that implements addition for the opcodes ADD and ADDI.
pub struct ProgramChip;

impl ProgramChip {
    pub fn new() -> Self {
        Self {}
    }
}

impl<F: PrimeField> Chip<F> for ProgramChip {
    fn name(&self) -> String {
        "Program".to_string()
    }

    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.

        // Collect the number of times each instruction is called from the cpu events.
        // Store it as a map of PC -> count.
        let mut instruction_counts = HashMap::new();
        segment.cpu_events.clone().into_iter().for_each(|event| {
            let pc = event.pc;
            instruction_counts
                .entry(pc)
                .and_modify(|count| *count += 1)
                .or_insert(1);
        });

        let rows = segment
            .program
            .instructions
            .clone()
            .into_iter()
            .enumerate()
            .map(|(i, instruction)| {
                let pc = segment.program.pc_base + (i as u32 * 4);
                let mut row = [F::zero(); NUM_PROGRAM_COLS];
                let cols: &mut ProgramCols<F> = row.as_mut_slice().borrow_mut();
                cols.pc = F::from_canonical_u32(pc);
                cols.instruction.populate(instruction);
                cols.selectors.populate(instruction);
                cols.multiplicity =
                    F::from_canonical_usize(*instruction_counts.get(&pc).unwrap_or(&0));
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
}

impl<F> BaseAir<F> for ProgramChip {
    fn width(&self) -> usize {
        NUM_PROGRAM_COLS
    }
}

impl<AB> Air<AB> for ProgramChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &ProgramCols<AB::Var> = main.row_slice(0).borrow();

        // Dummy constraint of degree 3.
        builder.assert_eq(
            local.pc * local.pc * local.pc,
            local.pc * local.pc * local.pc,
        );

        // Contrain the interaction with CPU table
        builder.receive_program(
            local.pc,
            local.instruction,
            local.selectors,
            local.multiplicity,
        );
    }
}

#[cfg(test)]
mod tests {

    use std::{collections::BTreeMap, sync::Arc};

    use p3_baby_bear::BabyBear;

    use p3_matrix::dense::RowMajorMatrix;

    use crate::{
        program::ProgramChip,
        runtime::{Instruction, Opcode, Program, Segment},
        utils::Chip,
    };

    #[test]
    fn generate_trace() {
        // main:
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     add x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
        ];
        let mut segment = Segment {
            program: Arc::new(Program {
                instructions,
                pc_start: 0,
                pc_base: 0,
                memory_image: BTreeMap::new(),
            }),
            ..Default::default()
        };
        let chip = ProgramChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut segment);
        println!("{:?}", trace.values)
    }
}
