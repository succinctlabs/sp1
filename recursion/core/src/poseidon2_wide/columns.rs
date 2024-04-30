use std::mem::size_of;

use sp1_derive::AlignedBorrow;

use crate::memory::{MemoryReadSingleCols, MemoryReadWriteSingleCols};

use super::external::{NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, WIDTH};

pub(crate) enum Poseidon2Columns<T> {
    Wide(Poseidon2SboxCols<T>),
    Narrow(Poseidon2Cols<T>),
}

impl<T> Poseidon2Columns<T> {
    pub fn get_memory(&self) -> &Poseidon2MemCols<T> {
        match self {
            Poseidon2Columns::Wide(cols) => &cols.memory,
            Poseidon2Columns::Narrow(cols) => &cols.memory,
        }
    }

    pub fn get_memory_mut(&mut self) -> &mut Poseidon2MemCols<T> {
        match self {
            Poseidon2Columns::Wide(cols) => &mut cols.memory,
            Poseidon2Columns::Narrow(cols) => &mut cols.memory,
        }
    }

    pub fn get_external_state(&self, round: usize) -> &[T; WIDTH] {
        match self {
            Poseidon2Columns::Wide(cols) => &cols.external_rounds[round].state,
            Poseidon2Columns::Narrow(cols) => &cols.external_rounds[round].state,
        }
    }

    pub fn get_external_state_mut(&mut self, round: usize) -> &mut [T; WIDTH] {
        match self {
            Poseidon2Columns::Wide(cols) => &mut cols.external_rounds[round].state,
            Poseidon2Columns::Narrow(cols) => &mut cols.external_rounds[round].state,
        }
    }

    pub fn get_internal_state(&self) -> &[T; WIDTH] {
        match self {
            Poseidon2Columns::Wide(cols) => &cols.internal_rounds.state,
            Poseidon2Columns::Narrow(cols) => &cols.internal_rounds.state,
        }
    }

    pub fn get_internal_state_mut(&mut self) -> &mut [T; WIDTH] {
        match self {
            Poseidon2Columns::Wide(cols) => &mut cols.internal_rounds.state,
            Poseidon2Columns::Narrow(cols) => &mut cols.internal_rounds.state,
        }
    }

    pub fn get_internal_s0(&self) -> &[T; NUM_INTERNAL_ROUNDS - 1] {
        match self {
            Poseidon2Columns::Wide(cols) => &cols.internal_rounds.s0,
            Poseidon2Columns::Narrow(cols) => &cols.internal_rounds.s0,
        }
    }

    pub fn get_internal_s0_mut(&mut self) -> &mut [T; NUM_INTERNAL_ROUNDS - 1] {
        match self {
            Poseidon2Columns::Wide(cols) => &mut cols.internal_rounds.s0,
            Poseidon2Columns::Narrow(cols) => &mut cols.internal_rounds.s0,
        }
    }

    pub fn get_external_sbox(&self, round: usize) -> Option<&[T; WIDTH]> {
        match self {
            Poseidon2Columns::Wide(cols) => Some(&cols.external_rounds[round].sbox_deg_3),
            Poseidon2Columns::Narrow(_) => None,
        }
    }

    pub fn get_external_sbox_mut(&mut self, round: usize) -> Option<&mut [T; WIDTH]> {
        match self {
            Poseidon2Columns::Wide(cols) => Some(&mut cols.external_rounds[round].sbox_deg_3),
            Poseidon2Columns::Narrow(_) => None,
        }
    }

    pub fn get_internal_sbox(&self) -> Option<&[T; NUM_INTERNAL_ROUNDS]> {
        match self {
            Poseidon2Columns::Wide(cols) => Some(&cols.internal_rounds.sbox_deg_3),
            Poseidon2Columns::Narrow(_) => None,
        }
    }

    pub fn get_internal_sbox_mut(&mut self) -> Option<&mut [T; NUM_INTERNAL_ROUNDS]> {
        match self {
            Poseidon2Columns::Wide(cols) => Some(&mut cols.internal_rounds.sbox_deg_3),
            Poseidon2Columns::Narrow(_) => None,
        }
    }
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2MemCols<T> {
    pub timestamp: T,
    pub dst: T,
    pub left: T,
    pub right: T,
    pub input: [MemoryReadSingleCols<T>; WIDTH],
    pub output: [MemoryReadWriteSingleCols<T>; WIDTH],
    pub is_real: T,
}

pub const NUM_POSEIDON2_SBOX_COLS: usize = size_of::<Poseidon2SboxCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2SboxCols<T> {
    pub(crate) memory: Poseidon2MemCols<T>,
    pub(crate) external_rounds: [Poseidon2SBoxExternalRoundCols<T>; NUM_EXTERNAL_ROUNDS],
    pub(crate) internal_rounds: Poseidon2SBoxInternalRoundsCols<T>,
}

/// A grouping of columns for a single external round.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub(crate) struct Poseidon2SBoxExternalRoundCols<T> {
    pub(crate) state: [T; WIDTH],
    pub(crate) sbox_deg_3: [T; WIDTH],
}

pub const NUM_POSEIDON2_COLS: usize = size_of::<Poseidon2Cols<u8>>();

/// A grouping of columns for all of the internal rounds.
/// As an optimization, we can represent all of the internal rounds without columns for intermediate
/// states except for the 0th element. This is because the linear layer that comes after the sbox is
/// degree 1, so all state elements at the end can be expressed as a degree-3 polynomial of:
/// 1) the 0th state element at rounds prior to the current round
/// 2) the rest of the state elements at the beginning of the internal rounds
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub(crate) struct Poseidon2SBoxInternalRoundsCols<T> {
    pub(crate) state: [T; WIDTH],
    pub(crate) s0: [T; NUM_INTERNAL_ROUNDS - 1],
    pub(crate) sbox_deg_3: [T; NUM_INTERNAL_ROUNDS],
}

/// The column layout for the chip.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2Cols<T> {
    pub(crate) memory: Poseidon2MemCols<T>,
    pub(crate) external_rounds: [Poseidon2ExternalRoundCols<T>; NUM_EXTERNAL_ROUNDS],
    pub(crate) internal_rounds: Poseidon2InternalRoundsCols<T>,
}

/// A grouping of columns for a single external round.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub(crate) struct Poseidon2ExternalRoundCols<T> {
    pub(crate) state: [T; WIDTH],
}

/// A grouping of columns for all of the internal rounds.
/// As an optimization, we can represent all of the internal rounds without columns for intermediate
/// states except for the 0th element. This is because the linear layer that comes after the sbox is
/// degree 1, so all state elements at the end can be expressed as a degree-3 polynomial of:
/// 1) the 0th state element at rounds prior to the current round
/// 2) the rest of the state elements at the beginning of the internal rounds
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub(crate) struct Poseidon2InternalRoundsCols<T> {
    pub(crate) state: [T; WIDTH],
    pub(crate) s0: [T; NUM_INTERNAL_ROUNDS - 1],
}
