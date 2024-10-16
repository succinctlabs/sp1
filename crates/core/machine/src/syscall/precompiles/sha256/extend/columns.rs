use std::mem::size_of;

use sp1_derive::AlignedBorrow;

use crate::{
    memory::{MemoryReadCols, MemoryWriteCols},
    operations::{
        Add4Operation, FixedRotateRightOperation, FixedShiftRightOperation, IsZeroOperation,
        XorOperation,
    },
};

pub const NUM_SHA_EXTEND_COLS: usize = size_of::<ShaExtendCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ShaExtendCols<T> {
    /// Inputs.
    pub shard: T,
    pub nonce: T,
    pub clk: T,
    pub w_ptr: T,

    /// Control flags.
    pub i: T,

    /// g^n where g is generator with order 16 and n is the row number.
    pub cycle_16: T,

    /// Checks whether current row is start of a 16-row cycle. Bool result is stored in `result`.
    pub cycle_16_start: IsZeroOperation<T>,

    /// Checks whether current row is end of a 16-row cycle. Bool result is stored in `result`.
    pub cycle_16_end: IsZeroOperation<T>,

    /// Flags for when in the first, second, or third 16-row cycle.
    pub cycle_48: [T; 3],

    /// Whether the current row is the first of a 48-row cycle and is real.
    pub cycle_48_start: T,
    /// Whether the current row is the end of a 48-row cycle and is real.
    pub cycle_48_end: T,

    /// Inputs to `s0`.
    pub w_i_minus_15: MemoryReadCols<T>,
    pub w_i_minus_15_rr_7: FixedRotateRightOperation<T>,
    pub w_i_minus_15_rr_18: FixedRotateRightOperation<T>,
    pub w_i_minus_15_rs_3: FixedShiftRightOperation<T>,
    pub s0_intermediate: XorOperation<T>,

    /// `s0 := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)`.
    pub s0: XorOperation<T>,

    /// Inputs to `s1`.
    pub w_i_minus_2: MemoryReadCols<T>,
    pub w_i_minus_2_rr_17: FixedRotateRightOperation<T>,
    pub w_i_minus_2_rr_19: FixedRotateRightOperation<T>,
    pub w_i_minus_2_rs_10: FixedShiftRightOperation<T>,
    pub s1_intermediate: XorOperation<T>,

    /// `s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)`.
    pub s1: XorOperation<T>,

    /// Inputs to `s2`.
    pub w_i_minus_16: MemoryReadCols<T>,
    pub w_i_minus_7: MemoryReadCols<T>,

    /// `w[i] := w[i-16] + s0 + w[i-7] + s1`.
    pub s2: Add4Operation<T>,

    /// Result.
    pub w_i: MemoryWriteCols<T>,

    /// Selector.
    pub is_real: T,
}
