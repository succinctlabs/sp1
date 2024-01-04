use crate::{air::Word, runtime::Instruction, utils::IntoIteratorCurtaVM};

use core::borrow::{Borrow, BorrowMut};
use p3_air::AirBuilder;
use p3_field::PrimeField;
use std::iter::once;
use valida_derive::AlignedBorrow;

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
        self.opcode = F::from_canonical_u32(instruction.opcode as u32);
        self.op_a = instruction.op_a.into();
        self.op_b = instruction.op_b.into();
        self.op_c = instruction.op_c.into();
    }
}

impl<AB: AirBuilder, T: Into<AB::Expr> + Copy> IntoIteratorCurtaVM<AB, T> for InstructionCols<T> {
    fn into_iter(&self) -> <std::vec::Vec<AB::Expr> as std::iter::IntoIterator>::IntoIter {
        once(self.opcode.into())
            .chain(<Word<T> as IntoIteratorCurtaVM<AB, T>>::into_iter(
                &self.op_a,
            ))
            .chain(<Word<T> as IntoIteratorCurtaVM<AB, T>>::into_iter(
                &self.op_b,
            ))
            .chain(<Word<T> as IntoIteratorCurtaVM<AB, T>>::into_iter(
                &self.op_c,
            ))
            .collect::<Vec<_>>()
            .into_iter()
    }
}
