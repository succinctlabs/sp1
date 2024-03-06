use std::array::IntoIter;
use std::mem::size_of;
use std::ops::{Index, IndexMut};

use core::borrow::{Borrow, BorrowMut};
use p3_air::AirBuilder;
use p3_field::AbstractField;
use p3_field::Field;
use sp1_derive::AlignedBorrow;

use super::{SP1AirBuilder, Word};

/// The size of a `u64` word in bytes.
pub const WORD_U64_SIZE: usize = 8;

/// A word_u64 is a 64-bit value represented in an AIR.
#[derive(AlignedBorrow, Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct WordU64<T>(pub [T; WORD_U64_SIZE]);

impl<T> WordU64<T> {
    /// Applies `f` to each element of the word.
    pub fn map<F, S>(self, f: F) -> WordU64<S>
    where
        F: FnMut(T) -> S,
    {
        WordU64(self.0.map(f))
    }

    /// Extends a variable to a u64 word.
    pub fn extend_var<AB: SP1AirBuilder<Var = T>>(var: T) -> WordU64<AB::Expr> {
        WordU64([
            AB::Expr::zero() + var,
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
        ])
    }
}

impl<T: AbstractField> WordU64<T> {
    /// Extends a variable to a word.
    pub fn extend_expr<AB: SP1AirBuilder<Expr = T>>(expr: T) -> WordU64<AB::Expr> {
        WordU64([
            AB::Expr::zero() + expr,
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
        ])
    }
}

impl<F: Field> WordU64<F> {
    /// Converts a word to a u64.
    pub fn to_u64(&self) -> u64 {
        u64::from_le_bytes(self.0.map(|x| x.to_string().parse::<u8>().unwrap()))
    }
}

impl<V: Copy> WordU64<V> {
    /// Reduces a `u64` word to a single variable.
    pub fn reduce<AB: AirBuilder<Var = V>>(&self) -> AB::Expr {
        let base = (0..8)
            .map(|x| 1 << (8 * x))
            .map(AB::Expr::from_canonical_u64)
            .collect::<Vec<_>>();
        self.0
            .iter()
            .enumerate()
            .map(|(i, x)| base[i].clone() * *x)
            .sum()
    }

    // Convert a u64 word into two u32 words. The first word is the lower 32 bits, and the second
    /// word is the higher 32 bits.
    pub fn split_into_u32_chunks(self) -> (Word<V>, Word<V>) {
        let lo_bytes = [self[0], self[1], self[2], self[3]];
        let hi_bytes = [self[4], self[5], self[6], self[7]];

        (Word(lo_bytes), Word(hi_bytes))
    }

    /// Built a u64 word from two u32 words. The first word is the lower 32 bits, and the second
    /// word is the higher 32 bits.
    pub fn from_u32_word(lo: Word<V>, hi: Word<V>) -> Self {
        let result = [lo[0], lo[1], lo[2], lo[3], hi[0], hi[1], hi[2], hi[3]];
        WordU64(result)
    }
}

impl<T> Index<usize> for WordU64<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<T> IndexMut<usize> for WordU64<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<F: Field> From<u64> for WordU64<F> {
    fn from(value: u64) -> Self {
        let inner = value
            .to_le_bytes()
            .into_iter()
            .map(F::from_canonical_u8)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        WordU64(inner)
    }
}

impl<T> IntoIterator for WordU64<T> {
    type Item = T;
    type IntoIter = IntoIter<T, WORD_U64_SIZE>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
