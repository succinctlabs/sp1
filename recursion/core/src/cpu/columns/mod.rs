use crate::{air::IsExtZeroOperation, memory::MemoryReadWriteCols};
use sp1_derive::AlignedBorrow;

mod alu;
mod branch;
mod instruction;
mod jump;
mod opcode;
mod opcode_specific;

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

    pub instruction: InstructionCols<T>,
    pub selectors: OpcodeSelectorCols<T>,

    pub a: MemoryReadWriteCols<T>,
    pub b: MemoryReadWriteCols<T>,
    pub c: MemoryReadWriteCols<T>,

    pub alu: AluCols<T>,

    // result = operand_1 == operand_2;
    pub eq_1_2: IsExtZeroOperation<T>,

    pub is_real: T,
}
