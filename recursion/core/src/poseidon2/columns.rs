use sp1_derive::AlignedBorrow;

use crate::{memory::MemoryReadWriteSingleCols, poseidon2_wide::external::WIDTH};

/// The column layout for the chip.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2Cols<T: Copy> {
    pub clk: T,
    pub dst_input: T,
    pub left_input: T,
    pub right_input: T,
    pub rounds: [T; 24], // 1 round for memory input; 1 round for initialize; 8 rounds for external; 13 rounds for internal; 1 round for memory output
    pub round_specific_cols: RoundSpecificCols<T>,
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub union RoundSpecificCols<T: Copy> {
    computation: ComputationCols<T>,
    memory_access: MemAccessCols<T>,
}

// SAFETY: Each view is a valid interpretation of the underlying array.
impl<T: Copy> RoundSpecificCols<T> {
    pub fn computation(&self) -> &ComputationCols<T> {
        unsafe { &self.computation }
    }

    pub fn computation_mut(&mut self) -> &mut ComputationCols<T> {
        unsafe { &mut self.computation }
    }

    pub fn memory_access(&self) -> &MemAccessCols<T> {
        unsafe { &self.memory_access }
    }

    pub fn memory_access_mut(&mut self) -> &mut MemAccessCols<T> {
        unsafe { &mut self.memory_access }
    }
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct ComputationCols<T> {
    pub input: [T; WIDTH],
    pub add_rc: [T; WIDTH],
    pub sbox_deg_7: [T; WIDTH],
    pub output: [T; WIDTH],
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct MemAccessCols<T> {
    pub addr_first_half: T,
    pub addr_second_half: T,
    pub mem_access: [MemoryReadWriteSingleCols<T>; WIDTH],
}
