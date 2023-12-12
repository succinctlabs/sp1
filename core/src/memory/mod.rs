mod air;
pub mod trace;
use core::cmp::Ordering;

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

/// Order memory events by (address, clk) in lexicographic order.
impl PartialOrd for MemoryEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some((self.addr, self.clk).cmp(&(other.addr, other.clk)))
    }
}

impl Ord for MemoryEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.addr, self.clk).cmp(&(other.addr, other.clk))
    }
}
