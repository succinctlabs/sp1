use p3_air::AirBuilder;
use p3_field::{AbstractField, ExtensionField, Field};
use serde::{Deserialize, Serialize};
use sp1_derive::AlignedBorrow;
use sp1_stark::air::{BinomialExtension, ExtensionAirBuilder, SP1AirBuilder};

use std::ops::{Index, IndexMut};

use crate::runtime::D;

/// The smallest unit of memory that can be read and written to.
#[derive(
    AlignedBorrow, Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize,
)]
#[repr(C)]
pub struct Block<T>(pub [T; D]);

pub trait BlockBuilder: AirBuilder {
    fn assert_block_eq<Lhs: Into<Self::Expr>, Rhs: Into<Self::Expr>>(
        &mut self,
        lhs: Block<Lhs>,
        rhs: Block<Rhs>,
    ) {
        for (l, r) in lhs.0.into_iter().zip(rhs.0) {
            self.assert_eq(l, r);
        }
    }
}

impl<AB: AirBuilder> BlockBuilder for AB {}

impl<T> Block<T> {
    pub fn map<F, U>(self, f: F) -> Block<U>
    where
        F: FnMut(T) -> U,
    {
        Block(self.0.map(f))
    }

    pub fn ext<E>(&self) -> E
    where
        T: Field,
        E: ExtensionField<T>,
    {
        E::from_base_slice(&self.0)
    }
}

impl<T: Clone> Block<T> {
    pub fn as_extension<AB: ExtensionAirBuilder<Var = T>>(&self) -> BinomialExtension<AB::Expr> {
        let arr: [AB::Expr; 4] = self.0.clone().map(|x| AB::Expr::zero() + x);
        BinomialExtension(arr)
    }

    pub fn as_extension_from_base<AB: SP1AirBuilder<Var = T>>(
        &self,
        base: AB::Expr,
    ) -> BinomialExtension<AB::Expr> {
        let mut arr: [AB::Expr; 4] = self.0.clone().map(|_| AB::Expr::zero());
        arr[0] = base;

        BinomialExtension(arr)
    }
}

impl<T> From<[T; D]> for Block<T> {
    fn from(arr: [T; D]) -> Self {
        Self(arr)
    }
}

impl<T: AbstractField> From<T> for Block<T> {
    fn from(value: T) -> Self {
        Self([value, T::zero(), T::zero(), T::zero()])
    }
}

impl<T: Copy> From<&[T]> for Block<T> {
    fn from(slice: &[T]) -> Self {
        let arr: [T; D] = slice.try_into().unwrap();
        Self(arr)
    }
}

impl<T, I> Index<I> for Block<T>
where
    [T]: Index<I>,
{
    type Output = <[T] as Index<I>>::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(&self.0, index)
    }
}

impl<T, I> IndexMut<I> for Block<T>
where
    [T]: IndexMut<I>,
{
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(&mut self.0, index)
    }
}

impl<T> IntoIterator for Block<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, D>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
