use core::borrow::{Borrow, BorrowMut};
use core::mem::{size_of, transmute};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use valida_derive::AlignedBorrow;

use crate::cpu::{instruction_cols::InstructionCols, opcode_cols::OpcodeSelectors};
use crate::runtime::Runtime;
use crate::utils::{pad_to_power_of_two, Chip};

pub const NUM_PROGRAM_COLS: usize = size_of::<ProgramCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Default)]
pub struct ProgramCols<T> {
    pub pc: T,
    pub instruction: InstructionCols<T>,
    pub selectors: OpcodeSelectors<T>,
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
        "program".to_string()
    }

    fn generate_trace(&self, runtime: &mut Runtime) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let rows = runtime
            .program
            .instructions
            .clone()
            .into_par_iter()
            .enumerate()
            .map(|(i, instruction)| {
                let mut row = [F::zero(); NUM_PROGRAM_COLS];
                let cols: &mut ProgramCols<F> = unsafe { transmute(&mut row) };
                cols.pc = F::from_canonical_usize(i);
                cols.instruction.populate(instruction);
                cols.selectors.populate(instruction);
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
    AB: AirBuilder,
{
    fn eval(&self, _: &mut AB) {}
}

#[cfg(test)]
mod tests {

    use p3_baby_bear::BabyBear;

    use p3_matrix::dense::RowMajorMatrix;

    use crate::{
        program::ProgramChip,
        runtime::{Instruction, Opcode, Program, Runtime},
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
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Runtime::new(program);
        let chip = ProgramChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut runtime);
        println!("{:?}", trace.values)
    }
}
