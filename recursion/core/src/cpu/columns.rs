use core::mem::size_of;
use sp1_core::memory::{MemoryReadCols, MemoryWriteCols};
use sp1_core::operations::IsZeroOperation;
use sp1_derive::AlignedBorrow;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy, Debug)]
#[repr(C)]
pub struct CpuCols<T> {
    pub clk: T,
    pub pc: T,
    pub fp: T,

    pub a: MemoryWriteCols<T>,
    pub b: MemoryReadCols<T>,
    pub c: MemoryReadCols<T>,

    pub instruction: InstructionCols<T>,

    pub is_add: T,
    pub is_sub: T,
    pub is_mul: T,
    pub is_div: T,
    pub is_lw: T,
    pub is_sw: T,
    pub is_beq: T,
    pub is_bne: T,
    pub is_jal: T,
    pub is_jalr: T,

    // c = a + b;
    pub add_scratch: T,

    // c = a - b;
    pub sub_scratch: T,

    // c = a * b;
    pub mul_scratch: T,

    // c = a / b;
    pub div_scratch: T,

    // ext(c) = ext(a) + ext(b);
    pub add_ext_scratch: [T; 4],

    // ext(c) = ext(a) - ext(b);
    pub sub_ext_scratch: [T; 4],

    // ext(c) = ext(a) * ext(b);
    pub mul_ext_scratch: [T; 4],

    // ext(c) = ext(a) / ext(b);
    pub div_ext_scratch: [T; 4],

    // c = a == b;
    pub a_eq_b: IsZeroOperation<T>,

    pub is_real: T,
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
pub struct InstructionCols<T> {
    pub opcode: T,
    pub op_a: T,
    pub op_b: T,
    pub op_c: T,
    pub imm_b: T,
    pub imm_c: T,
}
