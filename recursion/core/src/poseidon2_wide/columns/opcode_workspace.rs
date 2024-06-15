use sp1_core::operations::IsZeroOperation;
use sp1_derive::AlignedBorrow;

use crate::{memory::MemoryReadWriteSingleCols, poseidon2_wide::WIDTH};

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub union OpcodeWorkspace<T: Copy> {
    compress: CompressWorkspace<T>,
    absorb: HashWorkspace<T>,
}

impl<T: Copy> OpcodeWorkspace<T> {
    pub fn compress(&self) -> &CompressWorkspace<T> {
        unsafe { &self.compress }
    }

    pub fn compress_mut(&mut self) -> &mut CompressWorkspace<T> {
        unsafe { &mut self.compress }
    }

    pub fn hash(&self) -> &HashWorkspace<T> {
        unsafe { &self.absorb }
    }

    pub fn hash_mut(&mut self) -> &mut HashWorkspace<T> {
        unsafe { &mut self.absorb }
    }
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct CompressWorkspace<T: Copy> {
    pub start_addr: T,
    pub memory_accesses: [MemoryReadWriteSingleCols<T>; WIDTH / 2],
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct HashWorkspace<T: Copy> {
    // Absorb and finalize
    pub previous_state: [T; WIDTH],
    pub state: [T; WIDTH],
    pub state_cursor: T, // Should be rotating within the same hash_num. Should be equal to  May not need it since memory_active bool columns may suffice.
    pub state_cursor_is_zero: IsZeroOperation<T>,

    // Absorb
    pub num_consumed: T, // Should be equal to min(remaining_len, WIDTH/2 - state_cursor)
    pub num_remaining: T, // Should be equal to previous_remaining_len - 8

    pub is_first_hash_row: T, // Only used for absorb
}
