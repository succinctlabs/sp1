use std::mem::transmute;
use std::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use sp1_derive::AlignedBorrow;

use crate::operations::poseidon2::{NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, WIDTH};
use crate::utils::indices_arr;

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

/// A column layout for a poseidon2 permutation with degree 3 constraints.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2Degree3Cols<T: Copy> {
    pub state: Poseidon2StateCols<T>,
    pub sbox_state: Poseidon2SBoxCols<T>,
}

/// A column layout for a poseidon2 permutation with degree 9 constraints.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2Degree9Cols<T: Copy> {
    pub state: Poseidon2StateCols<T>,
}

pub const GHOST: usize = NUM_INTERNAL_ROUNDS - 1;

/// A column layout for the intermediate states of a Poseidon2 AIR across all rounds.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2StateCols<T> {
    pub external_rounds_state: [[T; WIDTH]; NUM_EXTERNAL_ROUNDS],
    pub internal_rounds_state: [T; WIDTH],
    pub internal_rounds_s0: [T; GHOST],
    pub output_state: [T; WIDTH],
}

/// A column layout for the intermediate S-box states of a Poseidon2 AIR across all rounds.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2SBoxCols<T: Copy> {
    pub external_rounds_sbox_state: [[T; WIDTH]; NUM_EXTERNAL_ROUNDS],
    pub internal_rounds_sbox_state: [T; NUM_INTERNAL_ROUNDS],
}

/// Trait that describes getter functions for the permutation columns.
pub trait Poseidon2Cols<T: Copy> {
    fn external_rounds_state(&self) -> &[[T; WIDTH]];

    fn internal_rounds_state(&self) -> &[T; WIDTH];

    fn internal_rounds_s0(&self) -> &[T; NUM_INTERNAL_ROUNDS - 1];

    fn external_rounds_sbox(&self) -> Option<&[[T; WIDTH]; NUM_EXTERNAL_ROUNDS]>;

    fn internal_rounds_sbox(&self) -> Option<&[T; NUM_INTERNAL_ROUNDS]>;

    fn perm_output(&self) -> &[T; WIDTH];

    #[allow(clippy::type_complexity)]
    fn get_cols_mut(
        &mut self,
    ) -> (
        &mut [[T; WIDTH]],
        &mut [T; WIDTH],
        &mut [T; NUM_INTERNAL_ROUNDS - 1],
        Option<&mut [[T; WIDTH]; NUM_EXTERNAL_ROUNDS]>,
        Option<&mut [T; NUM_INTERNAL_ROUNDS]>,
        &mut [T; WIDTH],
    );
}

impl<T: Copy> Poseidon2Cols<T> for Poseidon2Degree3Cols<T> {
    fn external_rounds_state(&self) -> &[[T; WIDTH]] {
        &self.state.external_rounds_state
    }

    fn internal_rounds_state(&self) -> &[T; WIDTH] {
        &self.state.internal_rounds_state
    }

    fn internal_rounds_s0(&self) -> &[T; NUM_INTERNAL_ROUNDS - 1] {
        &self.state.internal_rounds_s0
    }

    fn external_rounds_sbox(&self) -> Option<&[[T; WIDTH]; NUM_EXTERNAL_ROUNDS]> {
        Some(&self.sbox_state.external_rounds_sbox_state)
    }

    fn internal_rounds_sbox(&self) -> Option<&[T; NUM_INTERNAL_ROUNDS]> {
        Some(&self.sbox_state.internal_rounds_sbox_state)
    }

    fn perm_output(&self) -> &[T; WIDTH] {
        &self.state.output_state
    }

    fn get_cols_mut(
        &mut self,
    ) -> (
        &mut [[T; WIDTH]],
        &mut [T; WIDTH],
        &mut [T; NUM_INTERNAL_ROUNDS - 1],
        Option<&mut [[T; WIDTH]; NUM_EXTERNAL_ROUNDS]>,
        Option<&mut [T; NUM_INTERNAL_ROUNDS]>,
        &mut [T; WIDTH],
    ) {
        (
            &mut self.state.external_rounds_state,
            &mut self.state.internal_rounds_state,
            &mut self.state.internal_rounds_s0,
            Some(&mut self.sbox_state.external_rounds_sbox_state),
            Some(&mut self.sbox_state.internal_rounds_sbox_state),
            &mut self.state.output_state,
        )
    }
}

impl<T: Copy> Poseidon2Cols<T> for Poseidon2Degree9Cols<T> {
    fn external_rounds_state(&self) -> &[[T; WIDTH]] {
        &self.state.external_rounds_state
    }

    fn internal_rounds_state(&self) -> &[T; WIDTH] {
        &self.state.internal_rounds_state
    }

    fn internal_rounds_s0(&self) -> &[T; NUM_INTERNAL_ROUNDS - 1] {
        &self.state.internal_rounds_s0
    }

    fn external_rounds_sbox(&self) -> Option<&[[T; WIDTH]; NUM_EXTERNAL_ROUNDS]> {
        None
    }

    fn internal_rounds_sbox(&self) -> Option<&[T; NUM_INTERNAL_ROUNDS]> {
        None
    }

    fn perm_output(&self) -> &[T; WIDTH] {
        &self.state.output_state
    }

    fn get_cols_mut(
        &mut self,
    ) -> (
        &mut [[T; WIDTH]],
        &mut [T; WIDTH],
        &mut [T; NUM_INTERNAL_ROUNDS - 1],
        Option<&mut [[T; WIDTH]; NUM_EXTERNAL_ROUNDS]>,
        Option<&mut [T; NUM_INTERNAL_ROUNDS]>,
        &mut [T; WIDTH],
    ) {
        (
            &mut self.state.external_rounds_state,
            &mut self.state.internal_rounds_state,
            &mut self.state.internal_rounds_s0,
            None,
            None,
            &mut self.state.output_state,
        )
    }
}

/// Convert a row to a mutable [`Poseidon2Cols`] instance.
pub fn permutation_mut<'a, 'b: 'a, T, const DEGREE: usize>(
    row: &'b mut [T],
) -> Box<&'b mut (dyn Poseidon2Cols<T> + 'a)>
where
    T: Copy,
{
    if DEGREE == 3 {
        let start = POSEIDON2_DEGREE3_COL_MAP.state.external_rounds_state[0][0];
        let end = start + size_of::<Poseidon2Degree3Cols<u8>>();
        let convert: &mut Poseidon2Degree3Cols<T> = row[start..end].borrow_mut();
        Box::new(convert)
    } else if DEGREE == 9 || DEGREE == 17 {
        let start = POSEIDON2_DEGREE9_COL_MAP.state.external_rounds_state[0][0];
        let end = start + size_of::<Poseidon2Degree9Cols<u8>>();

        let convert: &mut Poseidon2Degree9Cols<T> = row[start..end].borrow_mut();
        Box::new(convert)
    } else {
        panic!("Unsupported degree");
    }
}

/// Convert a row to an immutable [`Poseidon2Cols`] instance.
pub fn permutation<'a, 'b: 'a, T, const DEGREE: usize>(
    row: &'b [T],
) -> Box<dyn Poseidon2Cols<T> + 'a>
where
    T: Copy,
{
    if DEGREE == 3 {
        let start = POSEIDON2_DEGREE3_COL_MAP.state.external_rounds_state[0][0];
        let end = start + size_of::<Poseidon2Degree3Cols<u8>>();
        let convert: Poseidon2Degree3Cols<T> = *row[start..end].borrow();
        Box::new(convert)
    } else if DEGREE == 9 || DEGREE == 17 {
        let start = POSEIDON2_DEGREE9_COL_MAP.state.external_rounds_state[0][0];
        let end = start + size_of::<Poseidon2Degree9Cols<u8>>();

        let convert: Poseidon2Degree9Cols<T> = *row[start..end].borrow();
        Box::new(convert)
    } else {
        panic!("Unsupported degree");
    }
}
