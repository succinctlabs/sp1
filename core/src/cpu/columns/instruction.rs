use core::borrow::{Borrow, BorrowMut};
use p3_field::PrimeField;
use std::mem::size_of;
use std::{iter::once, vec::IntoIter};
use valida_derive::AlignedBorrow;

use crate::{air::Word, runtime::Instruction};

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
}

impl<F: PrimeField> InstructionCols<F> {
    pub fn populate(&mut self, instruction: Instruction) {
        self.opcode = instruction.opcode.as_field::<F>();
        self.op_a = instruction.op_a.into();
        self.op_b = instruction.op_b.into();
        self.op_c = instruction.op_c.into();
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
            .collect::<Vec<_>>()
            .into_iter()
    }
}
