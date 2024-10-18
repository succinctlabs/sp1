use std::mem::{size_of, transmute};

use sp1_core_machine::utils::indices_arr;
use sp1_derive::AlignedBorrow;

use crate::chips::poseidon2_skinny::{NUM_INTERNAL_ROUNDS, WIDTH};

pub mod preprocessed;

pub const NUM_POSEIDON2_COLS: usize = size_of::<Poseidon2<u8>>();
const fn make_col_map_degree9() -> Poseidon2<usize> {
    let indices_arr = indices_arr::<NUM_POSEIDON2_COLS>();
    unsafe { transmute::<[usize; NUM_POSEIDON2_COLS], Poseidon2<usize>>(indices_arr) }
}
pub const POSEIDON2_DEGREE9_COL_MAP: Poseidon2<usize> = make_col_map_degree9();

/// Struct for the poseidon2 skinny non preprocessed column.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2<T: Copy> {
    pub state_var: [T; WIDTH],
    pub internal_rounds_s0: [T; NUM_INTERNAL_ROUNDS - 1],
}
