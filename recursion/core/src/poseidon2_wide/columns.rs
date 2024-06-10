use std::mem::size_of;

use sp1_derive::AlignedBorrow;

use crate::memory::{MemoryReadSingleCols, MemoryReadWriteSingleCols};

use super::external::{NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, WIDTH};

pub const NUM_POSEIDON2_COLS: usize = size_of::<Poseidon2Cols<u8>>();

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2CompressInput<T> {
    pub clk: T,
    pub dst_ptr: T,
    pub left_ptr: T,
    pub right_ptr: T,
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2AbsorbInput<T> {
    pub clk: T,
    pub input_ptr: T,
    pub len: T,
    pub hash_num: T,
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2FinalizeInput<T> {
    pub clk: T,
    pub hash_num: T,
    pub output_ptr: T,
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub union Poseidon2InputEnum<T: Copy> {
    compress: Poseidon2CompressInput<T>,
    absorb: Poseidon2AbsorbInput<T>,
    finalize: Poseidon2FinalizeInput<T>,
}

impl<T: Copy> Poseidon2InputEnum<T> {
    pub fn compress(&self) -> &Poseidon2CompressInput<T> {
        unsafe { &self.compress }
    }

    pub fn compress_mut(&mut self) -> &mut Poseidon2CompressInput<T> {
        unsafe { &mut self.compress }
    }

    pub fn absorb(&self) -> &Poseidon2AbsorbInput<T> {
        unsafe { &self.absorb }
    }

    pub fn absorb_mut(&mut self) -> &mut Poseidon2AbsorbInput<T> {
        unsafe { &mut self.absorb }
    }

    pub fn finalize(&self) -> &Poseidon2FinalizeInput<T> {
        unsafe { &self.finalize }
    }

    pub fn finalize_mut(&mut self) -> &mut Poseidon2FinalizeInput<T> {
        unsafe { &mut self.finalize }
    }
}

#[derive(AlignedBorrow, Clone, Copy)]
pub struct Poseidon2Compress<T: Copy> {
    pub left_input_memory: [MemoryReadSingleCols<T>; WIDTH / 2],
    pub right_input_memory: [MemoryReadSingleCols<T>; WIDTH / 2],
    pub permutation_rows: Poseidon2Permutation<T>,
}

#[derive(AlignedBorrow, Clone, Copy)]
pub struct Poseidon2Absorb<T: Copy> {
    pub input_memory: [MemoryReadSingleCols<T>; WIDTH / 2], // address will be start_addr + sum()
    pub previous_output: [T; WIDTH],
    pub clk_diff_bits: [T; 4],
    pub is_first_row: T,
    pub input_addr: T,
    pub input_len: T,
    pub input_state_start_idx: T,
    pub num_input_consumed: T,
    pub permutation_rows: Poseidon2Permutation<T>,
}

#[derive(AlignedBorrow, Clone, Copy)]
pub struct Poseidon2Output<T: Copy> {
    pub previous_output: [T; WIDTH],
    pub output_memory: [MemoryReadWriteSingleCols<T>; WIDTH],
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub union Poseidon2OpcodeSpecific<T: Copy> {
    compress: Poseidon2Compress<T>,
    absorb: Poseidon2Absorb<T>,
    output: Poseidon2Output<T>,
}

impl<T: Copy> Poseidon2OpcodeSpecific<T> {
    pub fn compress(&self) -> &Poseidon2Compress<T> {
        unsafe { &self.compress }
    }

    pub fn compress_mut(&mut self) -> &mut Poseidon2Compress<T> {
        unsafe { &mut self.compress }
    }

    pub fn absorb(&self) -> &Poseidon2Absorb<T> {
        unsafe { &self.absorb }
    }

    pub fn absorb_mut(&mut self) -> &mut Poseidon2Absorb<T> {
        unsafe { &mut self.absorb }
    }

    pub fn output(&self) -> &Poseidon2Output<T> {
        unsafe { &self.output }
    }

    pub fn output_mut(&mut self) -> &mut Poseidon2Output<T> {
        unsafe { &mut self.output }
    }
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2Permutation<T: Copy> {
    external_rounds_state: [[T; WIDTH]; NUM_EXTERNAL_ROUNDS],
    internal_rounds_state: [T; WIDTH],
    internal_rounds_s0: [T; NUM_INTERNAL_ROUNDS - 1],
    external_rounds_sbox: [[T; WIDTH]; NUM_EXTERNAL_ROUNDS],
    internal_rounds_sbox: [T; NUM_INTERNAL_ROUNDS],
    output_state: [T; WIDTH],
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2Cols<T: Copy> {
    pub is_compress: T,
    pub is_absorb: T,
    pub is_finalize: T,
    pub syscall_input: Poseidon2InputEnum<T>,
    pub cols: Poseidon2OpcodeSpecific<T>,
    pub state_cursor: [T; WIDTH / 2], // Only used for absorb
}
