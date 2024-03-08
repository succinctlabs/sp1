pub mod air;
pub mod columns;

pub use crate::{memory::MemoryRecord, runtime::Instruction};

#[derive(Debug, Clone)]
pub struct CpuEvent<F> {
    pub clk: F,
    pub pc: F,
    pub fp: F,
    pub instruction: Instruction<F>,
    pub a: F,
    pub a_record: Option<MemoryRecord<F>>,
    pub b: F,
    pub b_record: Option<MemoryRecord<F>>,
    pub c: F,
    pub c_record: Option<MemoryRecord<F>>,
}

#[derive(Default)]
pub struct CpuChip<F> {
    _phantom: std::marker::PhantomData<F>,
}
