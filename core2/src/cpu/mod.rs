use valida_machine::{Operands, Word};

pub struct CpuEvent {
    pub clk: u32,
    pub fp: u32,
    pub pc: u32,
    pub opcode: u32,
    pub operands: Operands<i32>,
}

struct CpuTrace {}

impl CpuTrace {
    fn generate_trace(events: Vec<CpuEvent>) {
        todo!();
    }
}
