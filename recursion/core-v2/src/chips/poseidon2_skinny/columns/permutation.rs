use std::{borrow::BorrowMut, mem::size_of};

use sp1_derive::AlignedBorrow;

use crate::chips::poseidon2_skinny::{NUM_INTERNAL_ROUNDS, WIDTH};

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
    pub state_var: [T; WIDTH],
    pub internal_rounds_s0: [T; NUM_INTERNAL_ROUNDS - 1],
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct PermutationSBoxState<T: Copy> {
    pub sbox_state: [T; max(WIDTH, NUM_INTERNAL_ROUNDS)],
}

/// Trait that describes getter functions for the permutation columns.
pub trait Permutation<T: Copy> {
    fn state(&self) -> &[T; WIDTH];

    fn internal_rounds_s0(&self) -> &[T; NUM_INTERNAL_ROUNDS - 1];

    fn sbox_state(&self) -> Option<&[T; max(WIDTH, NUM_INTERNAL_ROUNDS)]>;
}

/// Trait that describes setter functions for the permutation columns.
pub trait PermutationMut<T: Copy> {
    #[allow(clippy::type_complexity)]
    fn set_perm_state(
        &mut self,
        state: [T; WIDTH],
        internal_rounds_s0: [T; NUM_INTERNAL_ROUNDS - 1],
    );
    fn set_sbox_state(&mut self, sbox_state: Option<[T; max(WIDTH, NUM_INTERNAL_ROUNDS)]>);
}

/// Permutation columns struct with S-boxes.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct PermutationSBox<T: Copy> {
    pub state: PermutationState<T>,
    pub sbox_state: PermutationSBoxState<T>,
}

impl<T: Copy> Permutation<T> for PermutationSBox<T> {
    fn state(&self) -> &[T; WIDTH] {
        &self.state.state_var
    }

    fn internal_rounds_s0(&self) -> &[T; NUM_INTERNAL_ROUNDS - 1] {
        &self.state.internal_rounds_s0
    }

    fn sbox_state(&self) -> Option<&[T; max(WIDTH, NUM_INTERNAL_ROUNDS)]> {
        Some(&self.sbox_state.sbox_state)
    }
}

impl<T: Copy> PermutationMut<T> for PermutationSBox<T> {
    fn set_perm_state(
        &mut self,
        state: [T; WIDTH],
        internal_rounds_s0: [T; NUM_INTERNAL_ROUNDS - 1],
    ) {
        self.state.state_var = state;
        self.state.internal_rounds_s0 = internal_rounds_s0;
    }

    fn set_sbox_state(&mut self, sbox_state: Option<[T; max(WIDTH, NUM_INTERNAL_ROUNDS)]>) {
        if let Some(sbox_state) = sbox_state {
            self.sbox_state.sbox_state = sbox_state;
        }
    }
}

/// Permutation columns struct without S-boxes.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct PermutationNoSbox<T: Copy> {
    pub state: PermutationState<T>,
}

impl<T: Copy> Permutation<T> for PermutationNoSbox<T> {
    fn state(&self) -> &[T; WIDTH] {
        &self.state.state_var
    }

    fn internal_rounds_s0(&self) -> &[T; NUM_INTERNAL_ROUNDS - 1] {
        &self.state.internal_rounds_s0
    }

    fn sbox_state(&self) -> Option<&[T; max(WIDTH, NUM_INTERNAL_ROUNDS)]> {
        None
    }
}

impl<T: Copy> PermutationMut<T> for PermutationNoSbox<T> {
    fn set_perm_state(
        &mut self,
        state: [T; WIDTH],
        internal_rounds_s0: [T; NUM_INTERNAL_ROUNDS - 1],
    ) {
        self.state.state_var = state;
        self.state.internal_rounds_s0 = internal_rounds_s0;
    }

    fn set_sbox_state(&mut self, _sbox_state: Option<[T; max(WIDTH, NUM_INTERNAL_ROUNDS)]>) {}
}

/// Permutation columns struct without S-boxes and half of the external rounds.
/// In the past, all external rounds were stored in one row, so this was a distinct struct, but
/// now the structs don't track the number of external rounds.
pub type PermutationNoSboxHalfExternal<T> = PermutationNoSbox<T>;

pub fn permutation_mut<'a, 'b: 'a, T, const DEGREE: usize>(
    row: &'b mut [T],
) -> Box<dyn PermutationMut<T> + 'a>
where
    T: Copy,
{
    if DEGREE == 3 || DEGREE == 5 {
        let start = POSEIDON2_DEGREE3_COL_MAP.permutation_cols.state.state_var[0];
        let end = start + size_of::<PermutationSBox<u8>>();
        let convert: PermutationSBox<T> = *row[start..end].borrow_mut();
        Box::new(convert)
    } else if DEGREE == 9 || DEGREE == 17 {
        let start = POSEIDON2_DEGREE9_COL_MAP.permutation_cols.state.state_var[0];
        let end = start + size_of::<PermutationNoSbox<u8>>();

        let convert: PermutationNoSbox<T> = *row[start..end].borrow_mut();
        Box::new(convert)
    } else {
        panic!("Unsupported degree");
    }
}
