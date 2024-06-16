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

    // Absorb
    pub is_first_hash_row: T, // Is the first row of a hash invocation.
    pub num_remaining_rows: T,
    pub num_remaining_rows_is_zero: IsZeroOperation<T>,
    pub last_row_ending_cursor: T,
    pub last_row_ending_cursor_is_seven: IsZeroOperation<T>, // Needed when doing the (last_row_ending_cursor_is_seven + 1) % 8 calculation.
    pub last_row_ending_cursor_bitmap: [T; 3],

    // A number of materialized flags to deal with max contraint degree.
    pub is_syscall_is_not_last_row: T, // expected num_consumed == RATE - start_cursor, expected cursor == start_cursor
    pub is_syscall_is_last_row: T, // expected num_consumed == len, expected cursor == start_cursor
    pub not_syscall_not_last_row: T, // expected num_consumed == 8, expected cursor == 0;
    pub not_syscall_is_last_row: T, // expected num_consuemd == last_row_num_consumed, expected_corsor == 0
    pub is_last_row_ending_cursor_is_seven: T,
    pub is_last_row_ending_cursor_not_seven: T,
}

// virtual: num_consumed, start_cursor
