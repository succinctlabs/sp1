use crate::program::Instruction;
pub mod air;
pub mod trace;
pub struct CpuEvent {
    pub clk: u32,
    pub fp: i32,
    pub pc: u32,
    pub instruction: Instruction<i32>,
}
