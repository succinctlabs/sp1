use std::fmt::{Display, Formatter};

use self::opcodes::Opcode;

pub const OPERAND_ELEMENTS: usize = 5;
pub mod opcodes;

#[derive(Debug, Clone, Copy)]
pub struct Instruction<W> {
    pub opcode: Opcode,
    pub operands: Operands<W>,
}

#[derive(Debug, Clone)]
pub struct ProgramROM<W>(pub Vec<Instruction<W>>);

impl<W: Copy> ProgramROM<W> {
    pub fn get_instruction(&self, pc: u32) -> Instruction<W> {
        self.0[pc as usize]
    }
}

#[derive(Copy, Clone, Default, Debug)]
pub struct Operands<F>(pub [F; OPERAND_ELEMENTS]);

impl<W: Display> Display for Instruction<W> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ", self.opcode)?;
        for operand in self.operands.0.iter() {
            write!(f, "{} ", operand)?;
        }
        Ok(())
    }
}
