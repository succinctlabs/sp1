use std::mem::size_of;

use sp1_derive::AlignedBorrow;

use crate::poseidon2_wide::WIDTH;

pub const POSEIDON2_MEMORY_WIDTH: usize = size_of::<Memory<u8>>();

pub const POSEIDON2_MEMORY_PREPROCESSED_WIDTH: usize = size_of::<MemoryPreprocessed<u8>>();

/// Memory columns for the Poseidon2 circuit based precompile.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Memory<T> {
    pub input: [T; WIDTH],
    pub output: [T; WIDTH],
}

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct MemoryPreprocessed<T> {
    pub input_addr: [T; WIDTH],
    pub output_addr: [T; WIDTH],
    pub output_mult: [T; WIDTH],
}
