use std::mem::size_of;

use sp1_derive::AlignedBorrow;

use crate::memory::{MemoryReadSingleCols, MemoryReadWriteSingleCols};

use super::external::{NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, WIDTH};

/// An enum the encapsulates mutable references to a wide version of poseidon2 chip (contains
/// intermediate sbox colunns) and a narrow version of the poseidon2 chip (doesn't contain
/// intermediate sbox columns).
pub(crate) enum Poseidon2ColTypeMut<'a, T> {
    Wide(&'a mut Poseidon2SBoxCols<T>),
    Narrow(&'a mut Poseidon2Cols<T>),
}

impl<T> Poseidon2ColTypeMut<'_, T> {
    /// Returns mutable references to the poseidon2 columns and optional the intermediate sbox columns.
    #[allow(clippy::type_complexity)]
    pub fn get_cols_mut(
        &mut self,
    ) -> (
        &mut Poseidon2Cols<T>,
        Option<&mut [[T; WIDTH]; NUM_EXTERNAL_ROUNDS]>,
        Option<&mut [T; NUM_INTERNAL_ROUNDS]>,
    ) {
        match self {
            Poseidon2ColTypeMut::Wide(cols) => (
                &mut cols.poseidon2_cols,
                Some(&mut cols.external_rounds_sbox),
                Some(&mut cols.internal_rounds_sbox),
            ),
            Poseidon2ColTypeMut::Narrow(cols) => (cols, None, None),
        }
    }
}

/// An immutable version of Poseidon2ColTypeMut.
pub(crate) enum Poseidon2ColType<T> {
    Wide(Poseidon2SBoxCols<T>),
    Narrow(Poseidon2Cols<T>),
}

impl<T: Clone> Poseidon2ColType<T> {
    /// Returns reference to the poseidon2 columns.
    pub fn get_poseidon2_cols(&self) -> Poseidon2Cols<T> {
        match self {
            Poseidon2ColType::Wide(cols) => cols.poseidon2_cols.clone(),
            Poseidon2ColType::Narrow(cols) => cols.clone(),
        }
    }

    /// Returns the external sbox columns for the given round.
    pub const fn get_external_sbox(&self, round: usize) -> Option<&[T; WIDTH]> {
        match self {
            Poseidon2ColType::Wide(cols) => Some(&cols.external_rounds_sbox[round]),
            Poseidon2ColType::Narrow(_) => None,
        }
    }

    /// Returns the internal sbox columns.
    pub const fn get_internal_sbox(&self) -> Option<&[T; NUM_INTERNAL_ROUNDS]> {
        match self {
            Poseidon2ColType::Wide(cols) => Some(&cols.internal_rounds_sbox),
            Poseidon2ColType::Narrow(_) => None,
        }
    }
}

pub const NUM_POSEIDON2_COLS: usize = size_of::<Poseidon2Cols<u8>>();

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2Cols<T> {
    pub parameters_cols: Poseidon2Parameters<T>,
    pub memory_cols: [MemoryReadSingleCols<T>; WIDTH],
    pub permute_cols: Poseidon2PermuteCols<T>,
    pub is_real: T,
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2Parameters<T> {
    pub timestamp: T,
    pub operation_type: T, // 0 for hash, 1 for compress
    pub arg_0: T,          // input ptr for hash, left ptr for compress
    pub arg_1: T,          // len for hash, right ptr for compress
    pub output_ptr: T,
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2PermuteCols<T> {
    pub(crate) external_rounds_state: [[T; WIDTH]; NUM_EXTERNAL_ROUNDS],
    pub(crate) internal_rounds_state: [T; WIDTH],
    pub(crate) internal_rounds_s0: [T; NUM_INTERNAL_ROUNDS - 1],
    pub(crate) external_rounds_sbox: [[T; WIDTH]; NUM_EXTERNAL_ROUNDS],
    pub(crate) internal_rounds_sbox: [T; NUM_INTERNAL_ROUNDS],
}
