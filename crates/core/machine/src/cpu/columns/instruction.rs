use p3_field::PrimeField;
use sp1_core_executor::{Instruction, Register};
use sp1_derive::AlignedBorrow;
use sp1_stark::Word;
use std::{iter::once, mem::size_of, vec::IntoIter};

pub const NUM_INSTRUCTION_COLS: usize = size_of::<InstructionCols<u8>>();

/// The column layout for instructions.
#[derive(AlignedBorrow, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct InstructionCols<T> {
    /// The opcode for this cycle.
    pub opcode: T,

    /// The first operand for this instruction.
    pub op_a: Word<T>,

    /// The second operand for this instruction.
    pub op_b: Word<T>,

    /// The third operand for this instruction.
    pub op_c: Word<T>,

    /// Flags to indicate if op_a is register 0.
    pub op_a_0: T,
}

impl<F: PrimeField> InstructionCols<F> {
    pub fn populate(&mut self, instruction: Instruction) {
        self.opcode = instruction.opcode.as_field::<F>();
        self.op_a = instruction.op_a.into();
        self.op_b = instruction.op_b.into();
        self.op_c = instruction.op_c.into();

        self.op_a_0 = F::from_bool(instruction.op_a == Register::X0 as u32);
    }
}

impl<T> IntoIterator for InstructionCols<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        once(self.opcode)
            .chain(self.op_a)
            .chain(self.op_b)
            .chain(self.op_c)
            .chain(once(self.op_a_0))
            .collect::<Vec<_>>()
            .into_iter()
    }
}
