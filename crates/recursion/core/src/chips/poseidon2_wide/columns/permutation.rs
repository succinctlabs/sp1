use std::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use sp1_derive::AlignedBorrow;

use crate::chips::poseidon2_wide::{NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, WIDTH};

use super::{POSEIDON2_DEGREE3_COL_MAP, POSEIDON2_DEGREE9_COL_MAP};

pub const fn max(a: usize, b: usize) -> usize {
    if a > b {
        a
    } else {
        b
    }
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct PermutationState<T: Copy> {
    pub external_rounds_state: [[T; WIDTH]; NUM_EXTERNAL_ROUNDS],
    pub internal_rounds_state: [T; WIDTH],
    pub internal_rounds_s0: [T; NUM_INTERNAL_ROUNDS - 1],
    pub output_state: [T; WIDTH],
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct PermutationSBoxState<T: Copy> {
    pub external_rounds_sbox_state: [[T; WIDTH]; NUM_EXTERNAL_ROUNDS],
    pub internal_rounds_sbox_state: [T; NUM_INTERNAL_ROUNDS],
}

/// Trait that describes getter functions for the permutation columns.
pub trait Poseidon2<T: Copy> {
    fn external_rounds_state(&self) -> &[[T; WIDTH]];

    fn internal_rounds_state(&self) -> &[T; WIDTH];

    fn internal_rounds_s0(&self) -> &[T; NUM_INTERNAL_ROUNDS - 1];

    fn external_rounds_sbox(&self) -> Option<&[[T; WIDTH]; NUM_EXTERNAL_ROUNDS]>;

    fn internal_rounds_sbox(&self) -> Option<&[T; NUM_INTERNAL_ROUNDS]>;

    fn perm_output(&self) -> &[T; WIDTH];
}

/// Trait that describes setter functions for the permutation columns.
pub trait Poseidon2Mut<T: Copy> {
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

/// Permutation columns struct with S-boxes.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct PermutationSBox<T: Copy> {
    pub state: PermutationState<T>,
    pub sbox_state: PermutationSBoxState<T>,
}

impl<T: Copy> Poseidon2<T> for PermutationSBox<T> {
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
}

impl<T: Copy> Poseidon2Mut<T> for PermutationSBox<T> {
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

/// Permutation columns struct without S-boxes.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct PermutationNoSbox<T: Copy> {
    pub state: PermutationState<T>,
}

impl<T: Copy> Poseidon2<T> for PermutationNoSbox<T> {
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
}

impl<T: Copy> Poseidon2Mut<T> for PermutationNoSbox<T> {
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

/// Permutation columns struct without S-boxes and half of the external rounds.
/// In the past, all external rounds were stored in one row, so this was a distinct struct, but
/// now the structs don't track the number of external rounds.
pub type PermutationNoSboxHalfExternal<T> = PermutationNoSbox<T>;

pub fn permutation_mut<'a, 'b: 'a, T, const DEGREE: usize>(
    row: &'b mut [T],
) -> Box<&mut (dyn Poseidon2Mut<T> + 'a)>
where
    T: Copy,
{
    if DEGREE == 3 {
        let start = POSEIDON2_DEGREE3_COL_MAP.state.external_rounds_state[0][0];
        let end = start + size_of::<PermutationSBox<u8>>();
        let convert: &mut PermutationSBox<T> = row[start..end].borrow_mut();
        Box::new(convert)
    } else if DEGREE == 9 || DEGREE == 17 {
        let start = POSEIDON2_DEGREE9_COL_MAP.state.external_rounds_state[0][0];
        let end = start + size_of::<PermutationNoSbox<u8>>();

        let convert: &mut PermutationNoSbox<T> = row[start..end].borrow_mut();
        Box::new(convert)
    } else {
        panic!("Unsupported degree");
    }
}

pub fn permutation<'a, 'b: 'a, T, const DEGREE: usize>(row: &'b [T]) -> Box<dyn Poseidon2<T> + 'a>
where
    T: Copy,
{
    if DEGREE == 3 {
        let start = POSEIDON2_DEGREE3_COL_MAP.state.external_rounds_state[0][0];
        let end = start + size_of::<PermutationSBox<u8>>();
        let convert: PermutationSBox<T> = *row[start..end].borrow();
        Box::new(convert)
    } else if DEGREE == 9 || DEGREE == 17 {
        let start = POSEIDON2_DEGREE9_COL_MAP.state.external_rounds_state[0][0];
        let end = start + size_of::<PermutationNoSbox<u8>>();

        let convert: PermutationNoSbox<T> = *row[start..end].borrow();
        Box::new(convert)
    } else {
        panic!("Unsupported degree");
    }
}
