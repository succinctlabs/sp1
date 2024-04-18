pub mod air;
pub mod columns;

use crate::air::Block;
pub use crate::{memory::MemoryRecord, runtime::Instruction};

pub use air::*;
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
}

#[derive(Default)]
pub struct CpuChip<F> {
    _phantom: std::marker::PhantomData<F>,
}
