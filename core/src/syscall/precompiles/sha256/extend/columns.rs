use std::mem::size_of;

use sp1_derive::AlignedBorrow;

use crate::memory::MemoryReadCols;
use crate::memory::MemoryWriteCols;
use crate::operations::Add4Operation;
use crate::operations::FixedRotateRightOperation;
use crate::operations::FixedShiftRightOperation;
use crate::operations::XorOperation;

pub const NUM_SHA_EXTEND_COLS: usize = size_of::<ShaExtendCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ShaExtendCols<T> {
    /// Inputs.
    pub shard: T,
    pub clk: T,
    pub w_ptr: T,

    /// Control flags.
    pub i: T,
    pub cycle_16: T,
    pub cycle_16_minus_g: T,
    pub cycle_16_minus_g_inv: T,
    pub cycle_16_start: T,
    pub cycle_16_minus_one: T,
    pub cycle_16_minus_one_inv: T,
    pub cycle_16_end: T,
    pub cycle_48: [T; 3],
    pub cycle_48_start: T,
    pub cycle_48_end: T,

    /// Computing `s0`.
    pub w_i_minus_15: MemoryReadCols<T>,
    pub w_i_minus_15_rr_7: FixedRotateRightOperation<T>,
    pub w_i_minus_15_rr_18: FixedRotateRightOperation<T>,
    pub w_i_minus_15_rs_3: FixedShiftRightOperation<T>,
    pub s0_intermediate: XorOperation<T>,
    pub s0: XorOperation<T>,

    /// Computing `s1`.
    pub w_i_minus_2: MemoryReadCols<T>,
    pub w_i_minus_2_rr_17: FixedRotateRightOperation<T>,
    pub w_i_minus_2_rr_19: FixedRotateRightOperation<T>,
    pub w_i_minus_2_rs_10: FixedShiftRightOperation<T>,
    pub s1_intermediate: XorOperation<T>,
    pub s1: XorOperation<T>,

    /// Computing `s2`.
    pub w_i_minus_16: MemoryReadCols<T>,
    pub w_i_minus_7: MemoryReadCols<T>,
    pub s2: Add4Operation<T>,

    /// Result.
    pub w_i: MemoryWriteCols<T>,

    /// Selector.
    pub is_real: T,
}
