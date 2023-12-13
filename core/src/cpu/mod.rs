use crate::runtime::Instruction;
pub mod air;
pub mod trace;

#[derive(Debug, Copy, Clone)]
pub struct CpuEvent {
    pub clk: u32,
    pub pc: u32,
    pub instruction: Instruction,
    pub operands: [u32; 3],
}
