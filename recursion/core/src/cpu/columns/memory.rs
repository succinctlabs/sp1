use sp1_derive::AlignedBorrow;
use std::mem::size_of;

use crate::memory::MemoryReadWriteCols;

#[allow(dead_code)]
pub const NUM_MEMORY_COLS: usize = size_of::<MemoryCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryCols<T> {
    pub(crate) memory_addr: T,
    pub(crate) memory: MemoryReadWriteCols<T>,
}
