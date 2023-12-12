mod air;
pub mod trace;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemOp {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemoryEvent {
    pub clk: u32,
    pub addr: u32,
    pub op: MemOp,
    pub value: i32,
}

impl MemoryEvent {
    pub fn read(clk: u32, addr: u32, value: i32) -> Self {
        Self {
            op: MemOp::Read,
            clk,
            addr,
            value,
        }
    }

    pub fn write(clk: u32, addr: u32, value: i32) -> Self {
        Self {
            op: MemOp::Write,
            clk,
            addr,
            value,
        }
    }
}
