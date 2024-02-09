use core::borrow::{Borrow, BorrowMut};
use std::mem::size_of;
use valida_derive::AlignedBorrow;

use crate::air::Word;

pub const NUM_AUIPC_COLS: usize = size_of::<AUIPCCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AUIPCCols<T> {
    /// The current program counter.
    pub pc: Word<T>,
}
