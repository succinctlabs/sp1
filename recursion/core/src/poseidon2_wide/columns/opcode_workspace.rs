use sp1_derive::AlignedBorrow;

use crate::{
    memory::{MemoryReadSingleCols, MemoryReadWriteSingleCols},
    poseidon2_wide::WIDTH,
};

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub union OpcodeWorkspace<T: Copy> {
    compress: CompressWorkspace<T>,
    absorb: AbsorbWorkspace<T>,
    output: OutputWorkspace<T>,
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

    pub fn output(&self) -> &OutputWorkspace<T> {
        unsafe { &self.output }
    }

    pub fn output_mut(&mut self) -> &mut OutputWorkspace<T> {
        unsafe { &mut self.output }
    }
}

#[derive(AlignedBorrow, Clone, Copy)]
pub struct CompressWorkspace<T: Copy> {
    pub input: [MemoryReadSingleCols<T>; WIDTH],
}

#[derive(AlignedBorrow, Clone, Copy)]
pub struct AbsorbWorkspace<T: Copy> {
    pub input_memory: [MemoryReadSingleCols<T>; WIDTH / 2], // address will be start_addr + sum()
    pub previous_output: [T; WIDTH],
    pub clk_diff_bits: [T; 4],
    pub is_first_row: T,
    pub input_addr: T,
    pub input_len: T,
    pub input_state_start_idx: T,
    pub num_input_consumed: T,
}

#[derive(AlignedBorrow, Clone, Copy)]
pub struct OutputWorkspace<T: Copy> {
    pub output_memory: [MemoryReadWriteSingleCols<T>; WIDTH],
}
