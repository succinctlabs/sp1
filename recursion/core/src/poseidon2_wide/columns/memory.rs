use sp1_derive::AlignedBorrow;

use crate::{memory::MemoryReadWriteSingleCols, poseidon2_wide::WIDTH};

/// This struct is the columns for the WIDTH/2 sequential memory slots.
/// For compress rows, this is used for the first half of read/write from the permutation state.
/// For hash related rows, this is reading absorb input and writing finalize output.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Memory<T> {
    /// The first address of the memory sequence.
    pub start_addr: T,
    /// Bitmap if whether the memory address is accessed.  This is set to all 1 for compress and
    /// finalize rows.
    pub memory_slot_used: [T; WIDTH / 2],
    pub memory_accesses: [MemoryReadWriteSingleCols<T>; WIDTH / 2],
}
