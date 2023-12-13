use std::ops::{Index, IndexMut};

use core::borrow::{Borrow, BorrowMut};
use p3_air::AirBuilder;
use p3_field::Field;
use valida_derive::AlignedBorrow;

use super::AirVariable;

/// Using a 32-bit word size, we use four field elements to represent a 32-bit word.
const WORD_LEN: usize = 4;

/// An AIR representation of a word in the instruction set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, AlignedBorrow)]
pub struct Word<T>(pub [T; WORD_LEN]);

impl<AB: AirBuilder> AirVariable<AB> for Word<AB::Var> {
    fn size_of() -> usize {
        WORD_LEN
    }

    fn eval_is_valid(&self, _builder: &mut AB) {
        todo!()
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
