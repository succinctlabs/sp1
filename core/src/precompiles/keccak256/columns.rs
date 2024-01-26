use core::borrow::{Borrow, BorrowMut};
use core::mem::{offset_of, size_of};

use p3_keccak_air::KeccakCols as P3KeccakCols;

use crate::cpu::cols::cpu_cols::MemoryAccessCols;

use super::STATE_NUM_WORDS;

#[repr(C)]
pub(crate) struct KeccakCols<T> {
    pub p3_keccak_cols: P3KeccakCols<T>,

    pub segment: T,
    pub clk: T,

    pub state_mem: [MemoryAccessCols<T>; STATE_NUM_WORDS],
    pub state_addr: T,

    pub do_memory_check: T,

    pub is_real: T,
}

pub const NUM_KECCAK_COLS: usize = size_of::<KeccakCols<u8>>();
pub const P3_KECCAK_COLS_OFFSET: usize = offset_of!(KeccakCols<u8>, p3_keccak_cols);

impl<T> Borrow<KeccakCols<T>> for [T] {
    fn borrow(&self) -> &KeccakCols<T> {
        debug_assert_eq!(self.len(), NUM_KECCAK_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<KeccakCols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<KeccakCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut KeccakCols<T> {
        debug_assert_eq!(self.len(), NUM_KECCAK_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<KeccakCols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}
