use crate::{air::Block, memory::MemoryReadWriteCols};
use sp1_core::operations::IsZeroOperation;
use sp1_derive::AlignedBorrow;

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
    pub is_add: T,
    pub is_sub: T,
    pub is_mul: T,
    pub is_beq: T,
    pub is_bne: T,

    pub beq: T,
    pub bne: T,

    // c = a + b;
    pub add_scratch: T,

    // c = a - b;
    pub sub_scratch: T,

    // c = a * b;
    pub mul_scratch: T,

    // ext(c) = ext(a) + ext(b);
    pub add_ext_scratch: Block<T>,

    // ext(c) = ext(a) - ext(b);
    pub sub_ext_scratch: Block<T>,

    // ext(c) = ext(a) * ext(b);
    pub mul_ext_scratch: Block<T>,

    // c = a == b;
    pub a_eq_b: IsZeroOperation<T>,

    pub is_real: T,
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
pub struct InstructionCols<T> {
    pub opcode: T,
    pub op_a: T,
    pub op_b: Block<T>,
    pub op_c: Block<T>,
    pub imm_b: T,
    pub imm_c: T,
}
