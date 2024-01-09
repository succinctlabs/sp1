use std::mem::size_of;
use std::ops::{Index, IndexMut};

use core::borrow::{Borrow, BorrowMut};
use p3_field::Field;
use valida_derive::AlignedBorrow;

/// Using a 32-bit word size, we use four field elements to represent a 32-bit word.
const WORD_LEN: usize = 4;

/// An AIR representation of a word in the instruction set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, AlignedBorrow)]
pub struct Word<T>(pub [T; WORD_LEN]);

impl<T> Word<T> {
    pub fn map<F, S>(self, f: F) -> Word<S>
    where
        F: FnMut(T) -> S,
    {
        Word(self.0.map(f))
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

impl<F: Field> From<u32> for Word<F> {
    fn from(value: u32) -> Self {
        let inner = value
            .to_le_bytes()
            .iter()
            .map(|v| F::from_canonical_u8(*v))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        Word(inner)
    }
}

impl<T> IntoIterator for Word<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, WORD_LEN>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
