use crate::memory::Word;
use core::mem::size_of;
use sp1_derive::AlignedBorrow;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryInitCols<T> {
    pub addr: T,
    pub timestamp: T,
    pub value: Word<T>,
    pub is_real: T,
}
