use sp1_derive::AlignedBorrow;
use sp1_stark::Word;
use std::mem::size_of;

use crate::operations::BabyBearWordRangeChecker;

pub const NUM_JUMP_COLS: usize = size_of::<JumpCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct JumpCols<T> {
    /// The current program counter.
    pub pc: Word<T>,
    pub pc_range_checker: BabyBearWordRangeChecker<T>,

    /// The next program counter.
    pub next_pc: Word<T>,
    pub next_pc_range_checker: BabyBearWordRangeChecker<T>,

    // A range checker for `op_a` which may contain `pc + 4`.
    pub op_a_range_checker: BabyBearWordRangeChecker<T>,

    pub jal_nonce: T,
    pub jalr_nonce: T,
}
