use crate::{air::Block, memory::MemoryReadWriteCols};
use sp1_core::operations::IsZeroOperation;
use sp1_derive::AlignedBorrow;

mod alu;
mod instruction;
mod opcode;

pub use alu::*;
pub use instruction::*;
pub use opcode::*;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Debug)]
#[repr(C)]
pub struct CpuCols<T> {
    pub clk: T,
    pub pc: T,
    pub fp: T,

    pub a: MemoryReadWriteCols<T>,
    pub b: MemoryReadWriteCols<T>,
    pub c: MemoryReadWriteCols<T>,

    pub instruction: InstructionCols<T>,

    pub alu: AluCols<T>,

    // c = a == b;
    pub a_eq_b: IsZeroOperation<T>,

    pub is_real: T,
}
