use crate::program::Instruction;

pub struct CpuEvent {
    pub clk: u32,
    pub fp: i32,
    pub pc: u32,
    pub instruction: Instruction<i32>,
}

struct CpuTrace {}

impl CpuTrace {
    fn generate_trace(events: Vec<CpuEvent>) {
        todo!();
    }
}
