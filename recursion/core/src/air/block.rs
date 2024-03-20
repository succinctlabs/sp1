use p3_air::AirBuilder;
use p3_field::AbstractField;
use p3_field::ExtensionField;
use p3_field::Field;
use p3_field::PrimeField32;
use sp1_core::air::{BinomialExtension, SP1AirBuilder};
use sp1_derive::AlignedBorrow;

use std::ops::Index;

use crate::runtime::D;

/// The smallest unit of memory that can be read and written to.
#[derive(AlignedBorrow, Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Block<T>(pub [T; D]);

pub trait BlockBuilder: AirBuilder {
    fn assert_block_eq<Lhs: Into<Self::Expr>, Rhs: Into<Self::Expr>>(
        &mut self,
        lhs: Block<Lhs>,
        rhs: Block<Lhs>,
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
    pub fn as_extension<AB: SP1AirBuilder<Var = T>>(&self) -> BinomialExtension<AB::Expr> {
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

impl<F: PrimeField32> From<F> for Block<F> {
    fn from(value: F) -> Self {
        Self([value, F::zero(), F::zero(), F::zero()])
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

impl<T> IntoIterator for Block<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, D>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
