use valida_machine::Operands;
use valida_machine::{InstructionWord, Word};

pub struct AluEvent {
    pub clk: u32,
    pub opcode: u32,
    pub a: Word<u8>,
    pub b: Word<u8>,
    pub c: Word<u8>,
}

struct AluTrace {}

impl AluTrace {
    fn generate_trace(events: Vec<AluEvent>) {
        todo!();
    }
}
