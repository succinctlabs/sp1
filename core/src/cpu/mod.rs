use crate::disassembler::Instruction;

pub mod air;
pub mod instruction_cols;
pub mod opcode_cols;
pub mod trace;

#[derive(Debug, Copy, Clone)]
pub struct CpuEvent {
    pub clk: u32,
    pub pc: u32,
    pub instruction: Instruction,
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub memory_value: Option<u32>,
    pub memory_store_value: Option<u32>,
}
