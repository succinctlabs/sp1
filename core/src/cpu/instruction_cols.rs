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
        let opcode = match instruction.opcode {
            Opcode::ADDI => Opcode::ADD,
            Opcode::XORI => Opcode::XOR,
            Opcode::ORI => Opcode::OR,
            Opcode::ANDI => Opcode::AND,
            Opcode::SLLI => Opcode::SLL,
            Opcode::SRLI => Opcode::SRL,
            Opcode::SRAI => Opcode::SRA,
            Opcode::SLTI => Opcode::SLT,
            Opcode::SLTIU => Opcode::SLTU,
            _ => instruction.opcode,
        };
        self.opcode = F::from_canonical_u32(opcode as u32);
        let mut op_c = instruction.op_c;
        match instruction.opcode {
            Opcode::LUI => {
                // For LUI, we convert it to a SLL instruction with imm_b and imm_c turned on.
                // Additionally the op_c should be set to 12.
                // For the CPU table, we do this conversion in the runtimefor CPU events
                // but for the program table, we must do the conversion here.
                self.opcode = F::from_canonical_u32(Opcode::SLL as u32);
                op_c = 12;
            }
            Opcode::AUIPC => {
                // For AUIPC, we set the 3rd operand to imm_b << 12.
                op_c = instruction.op_b << 12;
            }
            _ => {}
        }
        self.op_a = instruction.op_a.into();
        self.op_b = instruction.op_b.into();
        self.op_c = op_c.into();
    }
}
