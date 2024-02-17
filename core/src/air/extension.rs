use std::{
    mem::size_of,
    ops::{Add, Mul},
};

use core::borrow::{Borrow, BorrowMut};
use itertools::Itertools;
use p3_field::{
    extension::{BinomialExtensionField, BinomiallyExtendable},
    field_to_array, AbstractExtensionField, AbstractField, Field,
};
use sp1_derive::AlignedBorrow;

use super::SP1AirBuilder;

#[derive(AlignedBorrow, Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Extension<T>(pub [T; 4]); // Degree 4 is hard coded for now.  TODO:  Change to a const generic

impl<V> Extension<V> {
    // Returns the one element of the extension field
    pub fn one<AB: SP1AirBuilder<Var = V>>() -> Extension<AB::Expr>
    where
        AB::Expr: AbstractField,
    {
        let one = AB::Expr::one();
        Extension(field_to_array(one))
    }

    // Converts a field element to extension element
    pub fn from<AB: SP1AirBuilder<Var = V>>(x: V) -> Extension<AB::Expr>
    where
        AB::Expr: From<V>,
    {
        Extension(field_to_array(x.into()))
    }

    // Negates an extension field Element
    pub fn neg<AB: SP1AirBuilder<Var = V>>(self) -> Extension<AB::Expr> {
        Extension(self.0.map(|x| AB::Expr::zero() - x))
    }

    // Adds an extension field element
    pub fn add<AB: SP1AirBuilder<Var = V>>(self, rhs: &Self) -> Extension<AB::Expr>
    where
        V: Add<V, Output = AB::Expr> + Copy,
    {
        let mut elements = Vec::new();

        for (e1, e2) in self.0.into_iter().zip_eq(rhs.0.into_iter()) {
            elements.push(e1 + e2);
        }

        Extension(elements.try_into().unwrap())
    }

    // Multiplies an extension field element
    pub fn mul<AB: SP1AirBuilder<Var = V>>(self, rhs: &Self) -> Extension<AB::Expr>
    where
        V: Mul<V, Output = AB::Expr> + Copy,
    {
        let mut elements = Vec::new();

        for (e1, e2) in self.0.into_iter().zip_eq(rhs.0.into_iter()) {
            elements.push(e1 * e2);
        }

        Extension(elements.try_into().unwrap())
    }
}

impl<F> From<BinomialExtensionField<F, 4>> for Extension<F>
where
    F: Field,
    F::F: BinomiallyExtendable<4>,
{
    fn from(value: BinomialExtensionField<F, 4>) -> Self {
        let base_slice = value.as_base_slice();

        Self(base_slice.try_into().unwrap())
    }
}
