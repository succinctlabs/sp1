use p3_field::PrimeField;
use sp1_core_executor::{Instruction, Opcode, Register};
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
    pub op_a: T,

    /// The second and third operand packed for this instruction.
    pub op_bc: Word<T>,

    /// Flags to indicate if op_a is register 0.
    pub op_a_0: T,
}

impl<F: PrimeField> InstructionCols<F> {
    pub fn populate(&mut self, instruction: Instruction) {
        self.opcode = instruction.opcode.as_field::<F>();
        self.op_a = F::from_canonical_u32(instruction.op_a);
        self.op_a_0 = F::from_bool(instruction.op_a == Register::X0 as u32);

        if instruction.opcode == Opcode::JAL {
            // We generate witnesses for J Type Instructions.
            assert!(instruction.imm_b && instruction.imm_c && instruction.op_c == 0);
            self.op_bc = instruction.op_b.into();
        } else if instruction.opcode == Opcode::AUIPC
            || (instruction.opcode == Opcode::ADD && instruction.imm_b)
        {
            // We generate witnesses for U Type Instructions.
            assert!(instruction.imm_b && instruction.imm_c);
            if instruction.opcode == Opcode::AUIPC {
                assert!(instruction.op_b == instruction.op_c);
            }
            if instruction.opcode == Opcode::ADD && instruction.imm_b {
                assert!(instruction.op_b == 0);
            }
            self.op_bc = instruction.op_c.into();
        } else if !instruction.imm_b && !instruction.imm_c {
            // We generate witnesses for R Type Instructions.
            self.op_bc[0] = F::from_canonical_u32(instruction.op_b);
            self.op_bc[1] = F::from_canonical_u32(instruction.op_c);
        } else if !instruction.imm_b && instruction.imm_c {
            // We generate witnesses for I, S, B Type Instructions.
            let op_c: Word<F> = instruction.op_c.into();
            assert!((-(1 << 15)..(1 << 15)).contains(&(instruction.op_c as i32)));
            assert!(op_c[2] == op_c[3]);
            self.op_bc = Word([F::from_canonical_u32(instruction.op_b), op_c[0], op_c[1], op_c[2]]);
        } else {
            assert!(instruction.opcode == Opcode::UNIMP);
        }
    }
}

impl<T> IntoIterator for InstructionCols<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        once(self.opcode)
            .chain(once(self.op_a))
            .chain(self.op_bc)
            .chain(once(self.op_a_0))
            .collect::<Vec<_>>()
            .into_iter()
    }
}
