use std::{borrow::BorrowMut, mem::size_of};

use sp1_derive::AlignedBorrow;

use crate::poseidon2_wide::{NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, WIDTH};

use super::{POSEIDON2_DEGREE3_COL_MAP, POSEIDON2_DEGREE9_COL_MAP};

/// Trait that describes getter functions for the permutation columns.
pub trait Permutation<T: Copy> {
    fn external_rounds_state(&self) -> &[[T; WIDTH]];

    fn internal_rounds_state(&self) -> &[T; WIDTH];

    fn internal_rounds_s0(&self) -> &[T; NUM_INTERNAL_ROUNDS - 1];

    fn external_rounds_sbox(&self) -> Option<&[[T; WIDTH]; NUM_EXTERNAL_ROUNDS]>;

    fn internal_rounds_sbox(&self) -> Option<&[T; NUM_INTERNAL_ROUNDS]>;

    fn perm_output(&self) -> &[T; WIDTH];
}

/// Trait that describes setter functions for the permutation columns.
pub trait PermutationMut<T: Copy> {
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
    pub external_rounds_state: [[T; WIDTH]; NUM_EXTERNAL_ROUNDS],
    pub internal_rounds_state: [T; WIDTH],
    pub internal_rounds_s0: [T; NUM_INTERNAL_ROUNDS - 1],
    pub external_rounds_sbox: [[T; WIDTH]; NUM_EXTERNAL_ROUNDS],
    pub internal_rounds_sbox: [T; NUM_INTERNAL_ROUNDS],
    pub output_state: [T; WIDTH],
}

impl<T: Copy> Permutation<T> for PermutationSBox<T> {
    fn external_rounds_state(&self) -> &[[T; WIDTH]] {
        &self.external_rounds_state
    }

    fn internal_rounds_state(&self) -> &[T; WIDTH] {
        &self.internal_rounds_state
    }

    fn internal_rounds_s0(&self) -> &[T; NUM_INTERNAL_ROUNDS - 1] {
        &self.internal_rounds_s0
    }

    fn external_rounds_sbox(&self) -> Option<&[[T; WIDTH]; NUM_EXTERNAL_ROUNDS]> {
        Some(&self.external_rounds_sbox)
    }

    fn internal_rounds_sbox(&self) -> Option<&[T; NUM_INTERNAL_ROUNDS]> {
        Some(&self.internal_rounds_sbox)
    }

    fn perm_output(&self) -> &[T; WIDTH] {
        &self.output_state
    }
}

impl<T: Copy> PermutationMut<T> for &mut PermutationSBox<T> {
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
            &mut self.external_rounds_state,
            &mut self.internal_rounds_state,
            &mut self.internal_rounds_s0,
            Some(&mut self.external_rounds_sbox),
            Some(&mut self.internal_rounds_sbox),
            &mut self.output_state,
        )
    }
}

/// Permutation columns struct without S-boxes.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct PermutationNoSbox<T: Copy> {
    pub external_rounds_state: [[T; WIDTH]; NUM_EXTERNAL_ROUNDS],
    pub internal_rounds_state: [T; WIDTH],
    pub internal_rounds_s0: [T; NUM_INTERNAL_ROUNDS - 1],
    pub output_state: [T; WIDTH],
}

impl<T: Copy> Permutation<T> for PermutationNoSbox<T> {
    fn external_rounds_state(&self) -> &[[T; WIDTH]] {
        &self.external_rounds_state
    }

    fn internal_rounds_state(&self) -> &[T; WIDTH] {
        &self.internal_rounds_state
    }

    fn internal_rounds_s0(&self) -> &[T; NUM_INTERNAL_ROUNDS - 1] {
        &self.internal_rounds_s0
    }

    fn external_rounds_sbox(&self) -> Option<&[[T; WIDTH]; NUM_EXTERNAL_ROUNDS]> {
        None
    }

    fn internal_rounds_sbox(&self) -> Option<&[T; NUM_INTERNAL_ROUNDS]> {
        None
    }

    fn perm_output(&self) -> &[T; WIDTH] {
        &self.output_state
    }
}

impl<T: Copy> PermutationMut<T> for &mut PermutationNoSbox<T> {
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
            &mut self.external_rounds_state,
            &mut self.internal_rounds_state,
            &mut self.internal_rounds_s0,
            None,
            None,
            &mut self.output_state,
        )
    }
}

/// Permutation columns struct without S-boxes and half of the external rounds.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct PermutationNoSboxHalfExternal<T: Copy> {
    pub external_rounds_state: [[T; WIDTH]; NUM_EXTERNAL_ROUNDS / 2],
    pub internal_rounds_state: [T; WIDTH],
    pub internal_rounds_s0: [T; NUM_INTERNAL_ROUNDS - 1],
    pub output_state: [T; WIDTH],
}

impl<T: Copy> Permutation<T> for PermutationNoSboxHalfExternal<T> {
    fn external_rounds_state(&self) -> &[[T; WIDTH]] {
        &self.external_rounds_state
    }

    fn internal_rounds_state(&self) -> &[T; WIDTH] {
        &self.internal_rounds_state
    }

    fn internal_rounds_s0(&self) -> &[T; NUM_INTERNAL_ROUNDS - 1] {
        &self.internal_rounds_s0
    }

    fn external_rounds_sbox(&self) -> Option<&[[T; WIDTH]; NUM_EXTERNAL_ROUNDS]> {
        None
    }

    fn internal_rounds_sbox(&self) -> Option<&[T; NUM_INTERNAL_ROUNDS]> {
        None
    }

    fn perm_output(&self) -> &[T; WIDTH] {
        &self.output_state
    }
}

impl<T: Copy> PermutationMut<T> for &mut PermutationNoSboxHalfExternal<T> {
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
            &mut self.external_rounds_state,
            &mut self.internal_rounds_state,
            &mut self.internal_rounds_s0,
            None,
            None,
            &mut self.output_state,
        )
    }
}

pub fn permutation_mut<'a, 'b: 'a, T, const DEGREE: usize>(
    row: &'b mut [T],
) -> Box<dyn PermutationMut<T> + 'a>
where
    T: Copy,
{
    if DEGREE == 3 {
        let start = POSEIDON2_DEGREE3_COL_MAP
            .permutation_cols
            .external_rounds_state[0][0];
        let end = start + size_of::<PermutationSBox<u8>>();
        let convert: &mut PermutationSBox<T> = row[start..end].borrow_mut();
        Box::new(convert)
    } else if DEGREE == 9 || DEGREE == 17 {
        let start = POSEIDON2_DEGREE9_COL_MAP
            .permutation_cols
            .external_rounds_state[0][0];
        let end = start + size_of::<PermutationNoSbox<u8>>();

        let convert: &mut PermutationNoSbox<T> = row[start..end].borrow_mut();
        Box::new(convert)
    } else {
        panic!("Unsupported degree");
    }
}
