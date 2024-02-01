use core::borrow::{Borrow, BorrowMut};
use core::mem::{offset_of, size_of};

use p3_keccak_air::KeccakCols as P3KeccakCols;
use valida_derive::AlignedBorrow;

use crate::memory::MemoryReadWriteCols;

use super::STATE_NUM_WORDS;

#[derive(AlignedBorrow)]
#[repr(C)]
pub(crate) struct KeccakCols<T> {
    pub p3_keccak_cols: P3KeccakCols<T>,

    pub segment: T,
    pub clk: T,

    pub state_mem: [MemoryReadWriteCols<T>; STATE_NUM_WORDS],
    pub state_addr: T,

    pub do_memory_check: T,

    pub is_real: T,
}

pub const NUM_KECCAK_COLS: usize = size_of::<KeccakCols<u8>>();
pub const P3_KECCAK_COLS_OFFSET: usize = offset_of!(KeccakCols<u8>, p3_keccak_cols);
