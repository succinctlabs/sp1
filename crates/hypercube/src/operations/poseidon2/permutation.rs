//! AIR columns for the Poseidon2 hash function.

use std::{
    borrow::BorrowMut,
    mem::{size_of, transmute},
};

use sp1_derive::AlignedBorrow;
use struct_reflection::{StructReflection, StructReflectionHelper};

use crate::{
    operations::poseidon2::{NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, WIDTH},
    util::indices_arr,
};

/// A column map for a Poseidon2 AIR with degree 3 constraints.
pub const POSEIDON2_DEGREE3_COL_MAP: Poseidon2Degree3Cols<usize> = make_col_map_degree3();

/// The number of columns in a Poseidon2 AIR with degree 3 constraints.
pub const NUM_POSEIDON2_DEGREE3_COLS: usize = size_of::<Poseidon2Degree3Cols<u8>>();

/// Create a column map for [`Poseidon2Degree3`].
const fn make_col_map_degree3() -> Poseidon2Degree3Cols<usize> {
    let indices_arr = indices_arr::<NUM_POSEIDON2_DEGREE3_COLS>();
    unsafe {
        transmute::<[usize; NUM_POSEIDON2_DEGREE3_COLS], Poseidon2Degree3Cols<usize>>(indices_arr)
    }
}

/// A column layout for a poseidon2 permutation with degree 3 constraints.
#[derive(AlignedBorrow, StructReflection, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2Degree3Cols<T: Copy> {
    /// The Poseidon2 hasher state.
    pub state: Poseidon2StateCols<T>,
}

/// The number of internal rounds minus one.
///
/// Making this constant explicit is useful for generating bindings.
pub const NUM_INTERNAL_ROUNDS_M1: usize = NUM_INTERNAL_ROUNDS - 1;

/// A column layout for the intermediate states of a Poseidon2 AIR across all rounds.
#[derive(AlignedBorrow, StructReflection, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2StateCols<T> {
    /// State for all external Poseidon2 rounds.
    pub external_rounds_state: [[T; WIDTH]; NUM_EXTERNAL_ROUNDS],
    /// State for the first Poseidon2 internal round.
    pub internal_rounds_state: [T; WIDTH],
    /// State for the first elements of the remaining internal Poseidon2 rounds.
    pub internal_rounds_s0: [T; NUM_INTERNAL_ROUNDS_M1],
    /// The final state of the Poseidon2 permutation.
    pub output_state: [T; WIDTH],
}

/// Trait that describes getter functions for the permutation columns.
pub trait Poseidon2Cols<T: Copy> {
    /// State for all external Poseidon2 rounds.
    fn external_rounds_state(&self) -> &[[T; WIDTH]];
    /// State for the first Poseidon2 internal round.
    fn internal_rounds_state(&self) -> &[T; WIDTH];
    /// State for the first elements of the remaining internal Poseidon2 rounds.
    fn internal_rounds_s0(&self) -> &[T; NUM_INTERNAL_ROUNDS_M1];
    /// The final state of the Poseidon2 permutation.
    fn perm_output(&self) -> &[T; WIDTH];

    /// A mutable view into the columns, as if `self` was [`Poseidon2StateCols`].
    #[allow(clippy::type_complexity)]
    fn get_cols_mut(
        &mut self,
    ) -> (&mut [[T; WIDTH]], &mut [T; WIDTH], &mut [T; NUM_INTERNAL_ROUNDS_M1], &mut [T; WIDTH]);
}

impl<T: Copy> Poseidon2Cols<T> for Poseidon2Degree3Cols<T> {
    fn external_rounds_state(&self) -> &[[T; WIDTH]] {
        &self.state.external_rounds_state
    }

    fn internal_rounds_state(&self) -> &[T; WIDTH] {
        &self.state.internal_rounds_state
    }

    fn internal_rounds_s0(&self) -> &[T; NUM_INTERNAL_ROUNDS_M1] {
        &self.state.internal_rounds_s0
    }

    fn perm_output(&self) -> &[T; WIDTH] {
        &self.state.output_state
    }

    fn get_cols_mut(
        &mut self,
    ) -> (&mut [[T; WIDTH]], &mut [T; WIDTH], &mut [T; NUM_INTERNAL_ROUNDS_M1], &mut [T; WIDTH])
    {
        (
            &mut self.state.external_rounds_state,
            &mut self.state.internal_rounds_state,
            &mut self.state.internal_rounds_s0,
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
    } else {
        panic!("Unsupported degree");
    }
}
