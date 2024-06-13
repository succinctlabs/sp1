use sp1_derive::AlignedBorrow;

use crate::{
    memory::{MemoryReadSingleCols, MemoryReadWriteSingleCols},
    poseidon2_wide::{RATE, WIDTH},
};

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub union OpcodeWorkspace<T: Copy> {
    compress: CompressWorkspace<T>,
    absorb: AbsorbWorkspace<T>,
}

impl<T: Copy> OpcodeWorkspace<T> {
    pub fn compress(&self) -> &CompressWorkspace<T> {
        unsafe { &self.compress }
    }

    pub fn compress_mut(&mut self) -> &mut CompressWorkspace<T> {
        unsafe { &mut self.compress }
    }

    pub fn absorb(&self) -> &AbsorbWorkspace<T> {
        unsafe { &self.absorb }
    }

    pub fn absorb_mut(&mut self) -> &mut AbsorbWorkspace<T> {
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
pub struct AbsorbWorkspace<T: Copy> {
    pub input_addr: T,

    // The first non zero element of this should equal to the state_cursor.
    // The sum of this is the total number of input elements consumed.
    // The last non zero element should equal the updated state_cursor.
    pub input_memory: [MemoryReadSingleCols<T>; RATE], // address will be start_addr + sum()
    pub input_memory_used: [T; RATE],

    pub input_cursor: T,
    pub previous_output: [T; WIDTH],

    pub clk_diff_bits: [T; 4],
    pub is_first_row: T,
}
