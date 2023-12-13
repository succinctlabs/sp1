use crate::runtime::Instruction;
pub mod air;
pub mod trace;

#[derive(Debug, Copy, Clone)]
pub struct CpuEvent {
    pub clk: u32,
    pub pc: u32,
    pub instruction: Instruction,
    pub operands: [u32; 3],
    pub addr: Option<u32>,
    pub memory_value: Option<u32>,
    pub branch_condition: Option<bool>,
}
