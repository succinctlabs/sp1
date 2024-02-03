use core::borrow::Borrow;
use core::borrow::BorrowMut;
use std::mem::size_of;

use valida_derive::AlignedBorrow;

use crate::memory::MemoryReadCols;
use crate::memory::MemoryReadWriteCols;
use crate::memory::MemoryWriteCols;
use crate::utils::ec::NUM_WORDS_FIELD_ELEMENT;

pub const NUM_POSEIDON2_EXTERNAL_COLS: usize = size_of::<Poseidon2ExternalCols<u8>>();
pub const POSEIDON2_DEFAULT_ROUNDS_F: usize = 8;
pub const _POSEIDON2_DEFAULT_ROUNDS_P: usize = 22;
// pub const POSEIDON2_DEFAULT_EXTERNAL_ROUNDS: usize = POSEIDON2_DEFAULT_ROUNDS_F / 2;
// TODO: Change this back to the above line.
pub const POSEIDON2_DEFAULT_EXTERNAL_ROUNDS: usize = 1;

// It's necessary to split the struct into two parts because of the const generic parameter.
// AlignedBorrow doesn't like a struct with more than one const generic parameter.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2ExternalCols<T>(
    pub Poseidon2ExternalColsConfigurable<T, NUM_WORDS_FIELD_ELEMENT>,
);

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2ExternalColsConfigurable<T, const NUM_WORDS_STATE: usize> {
    pub segment: T,
    pub clk: T,
    pub mem_read_clk: [T; NUM_WORDS_STATE],
    pub mem_write_clk: [T; NUM_WORDS_STATE],

    pub state_ptr: T,

    pub mem_reads: [MemoryReadCols<T>; NUM_WORDS_STATE],
    pub mem_writes: [MemoryWriteCols<T>; NUM_WORDS_STATE],
    pub mem_addr: [T; NUM_WORDS_STATE],

    pub is_external: T,

    pub is_real: T,
}

impl<T: Default, const NUM_WORDS_STATE: usize> Default
    for Poseidon2ExternalColsConfigurable<T, NUM_WORDS_STATE>
{
    fn default() -> Self {
        Self {
            segment: T::default(),
            clk: T::default(),
            mem_read_clk: core::array::from_fn(|_| T::default()),
            mem_write_clk: core::array::from_fn(|_| T::default()),
            state_ptr: T::default(),
            mem_reads: core::array::from_fn(|_| MemoryReadCols::<T>::default()),
            mem_writes: core::array::from_fn(|_| MemoryWriteCols::<T>::default()),
            mem_addr: core::array::from_fn(|_| T::default()),
            is_external: T::default(),
            is_real: T::default(),
        }
    }
}
