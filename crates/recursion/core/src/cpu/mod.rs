pub mod air;
pub mod columns;
mod trace;

use crate::air::Block;
pub use crate::{memory::MemoryRecord, runtime::Instruction};

pub use columns::*;

#[derive(Debug, Clone)]
pub struct CpuEvent<F> {
    pub clk: F,
    pub pc: F,
    pub fp: F,
    pub instruction: Instruction<F>,
    pub a: Block<F>,
    pub a_record: Option<MemoryRecord<F>>,
    pub b: Block<F>,
    pub b_record: Option<MemoryRecord<F>>,
    pub c: Block<F>,
    pub c_record: Option<MemoryRecord<F>>,
    pub memory_record: Option<MemoryRecord<F>>,
}

#[derive(Default)]
pub struct CpuChip<F, const L: usize> {
    pub fixed_log2_rows: Option<usize>,
    pub _phantom: std::marker::PhantomData<F>,
}
