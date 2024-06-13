use sp1_derive::AlignedBorrow;

use crate::{memory::MemoryReadWriteSingleCols, poseidon2_wide::WIDTH};

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Memory<T> {
    pub start_addr: T,
    pub memory_slot_used: [T; WIDTH / 2],
    pub memory_accesses: [MemoryReadWriteSingleCols<T>; WIDTH / 2],
}
