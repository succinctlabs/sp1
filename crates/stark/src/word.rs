use std::ops::{Index, IndexMut};

use crate::air::SP1AirBuilder;
use arrayref::array_ref;
use itertools::Itertools;
use p3_air::AirBuilder;
use p3_field::{AbstractField, Field};
use serde::{Deserialize, Serialize};
use sp1_derive::AlignedBorrow;
use sp1_primitives::consts::WORD_SIZE;
use std::array::IntoIter;

/// An array of four bytes to represent a 32-bit value.
///
/// We use the generic type `T` to represent the different representations of a byte, ranging from
/// a `u8` to a `AB::Var` or `AB::Expr`.
#[derive(
    AlignedBorrow, Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize,
)]
#[repr(C)]
pub struct Word<T>(pub [T; WORD_SIZE]);

impl<T> Word<T> {
    /// Applies `f` to each element of the word.
    pub fn map<F, S>(self, f: F) -> Word<S>
    where
        F: FnMut(T) -> S,
    {
        Word(self.0.map(f))
    }

    /// Extends a variable to a word.
    pub fn extend_var<AB: SP1AirBuilder<Var = T>>(var: T) -> Word<AB::Expr> {
        Word([AB::Expr::zero() + var, AB::Expr::zero(), AB::Expr::zero(), AB::Expr::zero()])
    }
}

impl<T: AbstractField> Word<T> {
    /// Extends a variable to a word.
    pub fn extend_expr<AB: SP1AirBuilder<Expr = T>>(expr: T) -> Word<AB::Expr> {
        Word([AB::Expr::zero() + expr, AB::Expr::zero(), AB::Expr::zero(), AB::Expr::zero()])
    }

    /// Returns a word with all zero expressions.
    #[must_use]
    pub fn zero<AB: SP1AirBuilder<Expr = T>>() -> Word<T> {
        Word([AB::Expr::zero(), AB::Expr::zero(), AB::Expr::zero(), AB::Expr::zero()])
    }
}

impl<F: Field> Word<F> {
    /// Converts a word to a u32.
    pub fn to_u32(&self) -> u32 {
        u32::from_le_bytes(self.0.map(|x| x.to_string().parse::<u8>().unwrap()))
    }
}

impl<V: Copy> Word<V> {
    /// Reduces a word to a single variable.
    pub fn reduce<AB: AirBuilder<Var = V>>(&self) -> AB::Expr {
        let base = [1, 1 << 8, 1 << 16, 1 << 24].map(AB::Expr::from_canonical_u32);
        self.0.iter().enumerate().map(|(i, x)| base[i].clone() * *x).sum()
    }
}

impl<T> Index<usize> for Word<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<T> IndexMut<usize> for Word<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<F: AbstractField> From<u32> for Word<F> {
    fn from(value: u32) -> Self {
        Word(value.to_le_bytes().map(F::from_canonical_u8))
    }
}

impl<T> IntoIterator for Word<T> {
    type Item = T;
    type IntoIter = IntoIter<T, WORD_SIZE>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T: Clone> FromIterator<T> for Word<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let elements = iter.into_iter().take(WORD_SIZE).collect_vec();

        Word(array_ref![elements, 0, WORD_SIZE].clone())
    }
}
