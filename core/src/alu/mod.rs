use crate::runtime::Opcode;

#[derive(Debug, Clone, Copy)]
pub struct AluEvent {
    pub clk: u32,
    pub opcode: Opcode,
    pub a: u32,
    pub b: u32,
    pub c: u32,
}
