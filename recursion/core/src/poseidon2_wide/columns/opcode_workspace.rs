use sp1_derive::AlignedBorrow;

use crate::{memory::MemoryReadWriteSingleCols, poseidon2_wide::WIDTH};

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
    pub previous_state: [T; WIDTH],
    pub state: [T; WIDTH],

    pub clk_diff_bits: [T; 4],
}
