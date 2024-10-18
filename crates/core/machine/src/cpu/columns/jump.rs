use sp1_derive::AlignedBorrow;
use sp1_stark::Word;
use std::mem::size_of;

use crate::operations::BabyBearWordRangeChecker;

pub const NUM_JUMP_COLS: usize = size_of::<JumpCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct JumpCols<T> {
    /// The current program counter. Important that this field be the first one in the struct, for
    /// the `get_most_significant_byte` function on `OpcodeSelectorCols` to be correct.
    pub pc: Word<T>,

    /// Important that this be the first field after the Word<T> field, in order for the
    /// `get_range_check_bit` function on `OpcodeSelectorCols` to be correct.
    pub pc_range_checker: T,

    /// The next program counter.
    pub next_pc: Word<T>,
    pub next_pc_range_checker: BabyBearWordRangeChecker<T>,

    // A range checker for `op_a` which may contain `pc + 4`.
    pub op_a_range_check_bit: T,

    pub jal_nonce: T,
    pub jalr_nonce: T,
}
