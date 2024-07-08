use std::mem::{size_of, transmute};

use permutation::{PermutationNoSbox, PermutationSBox};
use sp1_core::utils::indices_arr;
use sp1_derive::AlignedBorrow;

use super::{NUM_INTERNAL_ROUNDS, WIDTH};

pub mod dummy_interactions;
pub mod permutation;
pub mod preprocessed;

/// Trait for getter methods for Poseidon2 columns.
pub trait Poseidon2<'a, T: Copy + 'a>: std::fmt::Debug {
    fn state_var(&self) -> &[T; WIDTH];
    fn internal_rounds_s0(&self) -> &[T; NUM_INTERNAL_ROUNDS - 1];
    fn s_box_state(&self) -> Option<&[T; WIDTH]>;
}

/// Trait for setter methods for Poseidon2 columns. Only need the memory columns are populated mutably.
pub trait Poseidon2Mut<'a, T: Copy + 'a>: std::fmt::Debug {
    fn get_cols_mut(
        &mut self,
    ) -> (
        &mut [T; WIDTH],
        &mut [T; NUM_INTERNAL_ROUNDS - 1],
        Option<&mut [T; WIDTH]>,
    );
}

/// Enum to enable dynamic dispatch for the Poseidon2 columns.
#[allow(dead_code)]
#[derive(Debug)]
enum Poseidon2Enum<T: Copy + std::fmt::Debug> {
    P2Degree3(Poseidon2Degree3<T>),
    P2Degree9(Poseidon2Degree9<T>),
}

impl<'a, T: Copy + std::fmt::Debug + 'a> Poseidon2<'a, T> for Poseidon2Enum<T> {
    fn state_var(&self) -> &[T; WIDTH] {
        match self {
            Poseidon2Enum::P2Degree3(p) => p.state_var(),
            Poseidon2Enum::P2Degree9(p) => p.state_var(),
        }
    }

    fn internal_rounds_s0(&self) -> &[T; NUM_INTERNAL_ROUNDS - 1] {
        match self {
            Poseidon2Enum::P2Degree3(p) => p.internal_rounds_s0(),
            Poseidon2Enum::P2Degree9(p) => p.internal_rounds_s0(),
        }
    }

    fn s_box_state(&self) -> Option<&[T; WIDTH]> {
        match self {
            Poseidon2Enum::P2Degree3(p) => p.s_box_state(),
            Poseidon2Enum::P2Degree9(p) => p.s_box_state(),
        }
    }
}

/// Enum to enable dynamic dispatch for the Poseidon2 columns.
#[allow(dead_code)]
#[derive(Debug)]
enum Poseidon2MutEnum<'a, T: Copy + std::fmt::Debug> {
    P2Degree3(&'a mut Poseidon2Degree3<T>),
    P2Degree9(&'a mut Poseidon2Degree9<T>),
}

impl<'a, T: Copy + std::fmt::Debug + 'a> Poseidon2Mut<'a, T> for Poseidon2MutEnum<'a, T> {
    fn get_cols_mut(
        &mut self,
    ) -> (
        &mut [T; WIDTH],
        &mut [T; NUM_INTERNAL_ROUNDS - 1],
        Option<&mut [T; WIDTH]>,
    ) {
        match self {
            Poseidon2MutEnum::P2Degree3(p) => p.get_cols_mut(),
            Poseidon2MutEnum::P2Degree9(p) => p.get_cols_mut(),
        }
    }
}

pub const NUM_POSEIDON2_DEGREE3_COLS: usize = size_of::<Poseidon2Degree3<u8>>();

const fn make_col_map_degree3() -> Poseidon2Degree3<usize> {
    let indices_arr = indices_arr::<NUM_POSEIDON2_DEGREE3_COLS>();
    unsafe {
        transmute::<[usize; NUM_POSEIDON2_DEGREE3_COLS], Poseidon2Degree3<usize>>(indices_arr)
    }
}
pub const POSEIDON2_DEGREE3_COL_MAP: Poseidon2Degree3<usize> = make_col_map_degree3();

/// Struct for the poseidon2 chip that contains sbox columns.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2Degree3<T: Copy + std::fmt::Debug> {
    pub permutation_cols: PermutationSBox<T>,
}
impl<'a, T: Copy + std::fmt::Debug + 'a> Poseidon2<'a, T> for Poseidon2Degree3<T> {
    fn state_var(&self) -> &[T; WIDTH] {
        &self.permutation_cols.state.state_var
    }

    fn internal_rounds_s0(&self) -> &[T; NUM_INTERNAL_ROUNDS - 1] {
        &self.permutation_cols.state.internal_rounds_s0
    }

    fn s_box_state(&self) -> Option<&[T; WIDTH]> {
        Some(&self.permutation_cols.sbox_state.sbox_state)
    }
}

impl<'a, T: Copy + std::fmt::Debug + 'a> Poseidon2Mut<'a, T> for &'a mut Poseidon2Degree3<T> {
    fn get_cols_mut(
        &mut self,
    ) -> (
        &mut [T; WIDTH],
        &mut [T; NUM_INTERNAL_ROUNDS - 1],
        Option<&mut [T; WIDTH]>,
    ) {
        (
            &mut self.permutation_cols.state.state_var,
            &mut self.permutation_cols.state.internal_rounds_s0,
            Some(&mut self.permutation_cols.sbox_state.sbox_state),
        )
    }
}

pub const NUM_POSEIDON2_DEGREE9_COLS: usize = size_of::<Poseidon2Degree9<u8>>();
const fn make_col_map_degree9() -> Poseidon2Degree9<usize> {
    let indices_arr = indices_arr::<NUM_POSEIDON2_DEGREE9_COLS>();
    unsafe {
        transmute::<[usize; NUM_POSEIDON2_DEGREE9_COLS], Poseidon2Degree9<usize>>(indices_arr)
    }
}
pub const POSEIDON2_DEGREE9_COL_MAP: Poseidon2Degree9<usize> = make_col_map_degree9();

/// Struct for the poseidon2 chip that doesn't contain sbox columns.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2Degree9<T: Copy + std::fmt::Debug> {
    pub permutation_cols: PermutationNoSbox<T>,
}

impl<'a, T: Copy + std::fmt::Debug + 'a> Poseidon2<'a, T> for Poseidon2Degree9<T> {
    fn state_var(&self) -> &[T; WIDTH] {
        &self.permutation_cols.state.state_var
    }

    fn internal_rounds_s0(&self) -> &[T; NUM_INTERNAL_ROUNDS - 1] {
        &self.permutation_cols.state.internal_rounds_s0
    }

    fn s_box_state(&self) -> Option<&[T; WIDTH]> {
        None
    }
}

impl<'a, T: Copy + std::fmt::Debug + 'a> Poseidon2Mut<'a, T> for &'a mut Poseidon2Degree9<T> {
    fn get_cols_mut(
        &mut self,
    ) -> (
        &mut [T; WIDTH],
        &mut [T; NUM_INTERNAL_ROUNDS - 1],
        Option<&mut [T; WIDTH]>,
    ) {
        (
            &mut self.permutation_cols.state.state_var,
            &mut self.permutation_cols.state.internal_rounds_s0,
            None,
        )
    }
}
