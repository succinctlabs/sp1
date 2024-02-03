use core::borrow::Borrow;
use core::borrow::BorrowMut;
use std::mem::size_of;

use valida_derive::AlignedBorrow;

use crate::memory::MemoryReadWriteCols;
use crate::utils::ec::NUM_WORDS_FIELD_ELEMENT;

pub const NUM_POSEIDON2_EXTERNAL_COLS: usize = size_of::<Poseidon2ExternalCols<u8>>();
pub const POSEIDON2_DEFAULT_ROUNDS_F: usize = 8;
pub const _POSEIDON2_DEFAULT_ROUNDS_P: usize = 22;
pub const POSEIDON2_DEFAULT_EXTERNAL_ROUNDS: usize = POSEIDON2_DEFAULT_ROUNDS_F / 2;

// It's necessary to split the struct into two parts because of the const generic parameter.
// AlignedBorrow doesn't like a struct with more than one const generic parameter.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2ExternalCols<T>(
    pub Poseidon2ExternalColsConfigurable<T, NUM_WORDS_FIELD_ELEMENT>,
);

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2ExternalColsConfigurable<T, const N: usize> {
    pub segment: T,
    pub clk: T,

    pub state_ptr: T,

    pub mem: [MemoryReadWriteCols<T>; N],
    pub mem_addr: [T; N],

    pub is_external: T,

    pub is_real: T,
}

impl<T: Default, const N: usize> Default for Poseidon2ExternalColsConfigurable<T, N> {
    fn default() -> Self {
        Self {
            segment: T::default(),
            clk: T::default(),
            state_ptr: T::default(),
            mem: core::array::from_fn(|_| MemoryReadWriteCols::<T>::default()),
            mem_addr: core::array::from_fn(|_| T::default()),
            is_external: T::default(),
            is_real: T::default(),
        }
    }
}
