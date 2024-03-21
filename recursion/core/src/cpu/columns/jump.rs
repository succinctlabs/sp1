use sp1_derive::AlignedBorrow;
use std::mem::size_of;

#[allow(dead_code)]
pub const NUM_JUMP_COLS: usize = size_of::<JumpCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct JumpCols<T> {
    /// The current program counter.
    pub pc: T,

    /// THe next program counter.
    pub next_pc: T,
}
