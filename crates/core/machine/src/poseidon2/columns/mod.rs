use std::mem::{size_of, transmute};

use crate::utils::indices_arr;

pub use permutation::{Poseidon2Degree3Cols, Poseidon2Degree9Cols};
pub mod permutation;

/// A column map for a Poseidon2 AIR with degree 3 constraints.
pub const POSEIDON2_DEGREE3_COL_MAP: Poseidon2Degree3Cols<usize> = make_col_map_degree3();

/// A column map for a Poseidon2 AIR with degree 9 constraints.
pub const POSEIDON2_DEGREE9_COL_MAP: Poseidon2Degree9Cols<usize> = make_col_map_degree9();

/// The number of columns in a Poseidon2 AIR with degree 3 constraints.
pub const NUM_POSEIDON2_DEGREE3_COLS: usize = size_of::<Poseidon2Degree3Cols<u8>>();

/// The number of columns in a Poseidon2 AIR with degree 9 constraints.
pub const NUM_POSEIDON2_DEGREE9_COLS: usize = size_of::<Poseidon2Degree9Cols<u8>>();

/// Create a column map for [`Poseidon2Degree3`].
const fn make_col_map_degree3() -> Poseidon2Degree3Cols<usize> {
    let indices_arr = indices_arr::<NUM_POSEIDON2_DEGREE3_COLS>();
    unsafe {
        transmute::<[usize; NUM_POSEIDON2_DEGREE3_COLS], Poseidon2Degree3Cols<usize>>(indices_arr)
    }
}

/// Create a column map for [`Poseidon2Degree9`].
const fn make_col_map_degree9() -> Poseidon2Degree9Cols<usize> {
    let indices_arr = indices_arr::<NUM_POSEIDON2_DEGREE9_COLS>();
    unsafe {
        transmute::<[usize; NUM_POSEIDON2_DEGREE9_COLS], Poseidon2Degree9Cols<usize>>(indices_arr)
    }
}
