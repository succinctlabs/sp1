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

pub const DEGREE: usize = 4;

#[derive(AlignedBorrow, Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Extension<T>(pub [T; DEGREE]); // Degree 4 is hard coded for now.  TODO:  Change to a const generic

impl<E: AbstractField> Extension<E> {
    // Returns the one element of the extension field
    pub fn one<AB: SP1AirBuilder<Expr = E>>() -> Extension<AB::Expr>
    where
        AB::Expr: AbstractField,
    {
        let one = AB::Expr::one();
        Extension(field_to_array(one))
    }

    // Converts a field element to extension element
    pub fn from<AB: SP1AirBuilder<Expr = E>>(x: E) -> Extension<AB::Expr> {
        Extension(field_to_array(x))
    }

    // Negates an extension field Element
    pub fn neg<AB: SP1AirBuilder<Expr = E>>(self) -> Extension<AB::Expr> {
        Extension(self.0.map(|x| AB::Expr::zero() - x))
    }

    // Adds an extension field element
    pub fn add<AB: SP1AirBuilder<Expr = E>>(self, rhs: &Self) -> Extension<AB::Expr>
    where
        E: Add<E, Output = AB::Expr>,
    {
        let mut elements = Vec::new();

        for (e1, e2) in self.0.into_iter().zip_eq(rhs.0.clone().into_iter()) {
            elements.push(e1 + e2);
        }

        Extension(elements.try_into().unwrap())
    }

    // Subtracts an extension field element
    pub fn sub<AB: SP1AirBuilder<Expr = E>>(self, rhs: &Self) -> Extension<AB::Expr>
    where
        E: Add<E, Output = AB::Expr>,
    {
        let mut elements = Vec::new();

        for (e1, e2) in self.0.into_iter().zip_eq(rhs.0.clone().into_iter()) {
            elements.push(e1 - e2);
        }

        Extension(elements.try_into().unwrap())
    }

    // Multiplies an extension field element
    pub fn mul<AB: SP1AirBuilder<Expr = E>>(self, rhs: &Self) -> Extension<AB::Expr>
    where
        E: Mul<E, Output = AB::Expr>,
        E: From<AB::F>,
        AB::F: BinomiallyExtendable<DEGREE>,
    {
        let mut base_slice = [
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
        ];

        let self_base_slice = self.as_base_slice();
        let rhs_base_slice = rhs.as_base_slice();
        let w = AB::Expr::from(AB::F::w());

        for i in 0..DEGREE {
            for j in 0..DEGREE {
                if i + j >= DEGREE {
                    base_slice[i + j - DEGREE] +=
                        self_base_slice[i].clone() * w.clone() * rhs_base_slice[j].clone();
                } else {
                    base_slice[i + j] += self_base_slice[i].clone() * rhs_base_slice[j].clone();
                }
            }
        }

        Extension(base_slice.try_into().unwrap())
    }

    pub fn as_base_slice(&self) -> &[E] {
        &self.0
    }
}

impl<V> Extension<V> {
    // Converts a field element with var base elements to one with expr base elements.
    pub fn from_var<AB: SP1AirBuilder<Var = V>>(self) -> Extension<AB::Expr>
    where
        V: Into<AB::Expr>,
    {
        Extension(self.0.map(|x| x.into()))
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

impl<F: BinomiallyExtendable<4>> From<F> for Extension<F> {
    fn from(value: F) -> Self {
        let base_slice = value.as_base_slice();

        Self(base_slice.try_into().unwrap())
    }
}
