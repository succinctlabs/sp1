use crate::{memory::MemoryRecord, runtime::Instruction};

pub mod air;
pub mod columns;
pub mod trace;

#[derive(Debug, Copy, Clone)]
pub struct CpuEvent {
    pub segment: u32,
    pub clk: u32,
    pub pc: u32,
    pub instruction: Instruction,
    pub a: u32,
    pub a_record: Option<MemoryRecord>,
    pub b: u32,
    pub b_record: Option<MemoryRecord>,
    pub c: u32,
    pub c_record: Option<MemoryRecord>,
    pub memory: Option<u32>,
    pub memory_record: Option<MemoryRecord>,
}

pub struct CpuChip;

impl CpuChip {
    pub fn new() -> Self {
        Self {}
    }
}
