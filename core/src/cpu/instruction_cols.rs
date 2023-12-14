use crate::air::Word;
use crate::runtime::{Instruction, Opcode};
use core::borrow::{Borrow, BorrowMut};
use p3_field::PrimeField;
use valida_derive::AlignedBorrow;

#[derive(AlignedBorrow, Default, Debug)]
#[repr(C)]
pub struct InstructionCols<T> {
    // /// The opcode for this cycle.
    pub opcode: T,
    // /// The first operand for this instruction.
    pub op_a: Word<T>,
    // /// The second operand for this instruction.
    pub op_b: Word<T>,
    // /// The third operand for this instruction.
    pub op_c: Word<T>,
}

impl<F: PrimeField> InstructionCols<F> {
    pub fn populate(&mut self, instruction: Instruction) {
        self.opcode = F::from_canonical_u32(instruction.opcode as u32);
        match instruction.opcode {
            Opcode::LUI => {
                // For LUI, we convert it to a SLL instruction with imm_b and imm_c turned on.
                self.opcode = F::from_canonical_u32(Opcode::SLL as u32);
                assert_eq!(instruction.op_c as u32, 12);
            }
            Opcode::AUIPC => {
                // For AUIPC, we set the 3rd operand to imm_b << 12.
                assert_eq!(instruction.op_c as u32, instruction.op_b << 12);
            }
            _ => {}
        }
        self.op_a = instruction.op_a.into();
        self.op_b = instruction.op_b.into();
        self.op_c = instruction.op_c.into();
    }
}
