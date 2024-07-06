use std::mem::size_of;

use sp1_derive::AlignedBorrow;

use crate::poseidon2_wide::WIDTH;

pub const POSEIDON2_MEMORY_PREPROCESSED_WIDTH: usize = size_of::<MemoryPreprocessed<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct MemoryPreprocessed<T> {
    pub input_addr: [T; WIDTH],
    pub mult: [T; WIDTH],
}

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct RoundCountersPreprocessed<T> {
    pub is_external_round: T,
    pub is_internal_round: T,
    pub is_first_round: T,
    pub round_constants: [T; WIDTH],
}
