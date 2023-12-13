use crate::runtime::Opcode;
pub mod air;
pub mod trace;

#[derive(Debug, Copy, Clone)]
pub struct CpuEvent {
    pub clk: u32,
    pub pc: u32,
    pub opcode: Opcode,
    pub op_a: u32,
    pub op_b: u32,
    pub op_c: u32,
    pub a: u32,
    pub b: u32,
    pub c: u32,
}
