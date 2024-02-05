use std::array::IntoIter;
use std::ops::{Index, IndexMut};

use p3_field::Field;
// TODO: Do I still need this? can't i just use an array?

/// An array of fixed size.
///
/// `AlignedBorrow` is implemented for this type since it requires a single const generic parameter.
/// To use this in a struct with `AlignedBorrow`, you need to specify `SIZE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Array<T, const SIZE: usize>(pub [T; SIZE]);

impl<T: Default, const SIZE: usize> Default for Array<T, SIZE> {
    fn default() -> Self {
        Self(core::array::from_fn(|_| T::default()))
    }
}

impl<T, const SIZE: usize> Array<T, SIZE> {
    /// Applies `f` to each element of the word.
    pub fn map<F, S>(self, f: F) -> Array<S, SIZE>
    where
        F: FnMut(T) -> S,
    {
        Array(self.0.map(f))
    }
}

impl<T, const SIZE: usize> Index<usize> for Array<T, SIZE> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<T, const SIZE: usize> IndexMut<usize> for Array<T, SIZE> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<F: Field, const SIZE: usize> From<&[u32]> for Array<F, SIZE> {
    fn from(slice: &[u32]) -> Self {
        let inner = slice
            .iter()
            .map(|x| F::from_canonical_u32(*x))
            .collect::<Vec<_>>()
            .try_into()
            .expect("Failed to convert slice to Array: size mismatch");
        Array(inner)
    }
}

impl<F: Field, const SIZE: usize> From<[u32; SIZE]> for Array<F, SIZE> {
    fn from(array: [u32; SIZE]) -> Self {
        Array(array.map(F::from_canonical_u32))
    }
}

impl<T, const SIZE: usize> IntoIterator for Array<T, SIZE> {
    type Item = T;
    type IntoIter = IntoIter<T, SIZE>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
