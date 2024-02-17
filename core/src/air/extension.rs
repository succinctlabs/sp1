use std::{
    mem::size_of,
    ops::{Add, Mul},
};

use core::borrow::{Borrow, BorrowMut};
use itertools::Itertools;
use p3_field::AbstractField;
use sp1_derive::AlignedBorrow;

use super::SP1AirBuilder;

#[derive(AlignedBorrow, Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Extension<T>(pub [T; 4]); // Extension 4 is hard coded for now.  TODO:  Change to a const generic

impl<V> Extension<V> {
    // Converts a field element to extension element
    pub fn from<AB: SP1AirBuilder<Var = V>>(x: V) -> Extension<AB::Expr>
    where
        AB::Expr: From<V>,
    {
        let zero = AB::Expr::zero();
        let x_expr = x.into();
        Extension([zero.clone(), zero.clone(), zero, x_expr])
    }

    // Negates an extension field Element
    pub fn neg<AB: SP1AirBuilder<Var = V>>(self) -> Extension<AB::Expr> {
        Extension(self.0.map(|x| AB::Expr::zero() - x))
    }

    // Adds an extension field element
    pub fn add<AB: SP1AirBuilder<Var = V>>(self, rhs: &Self) -> Extension<AB::Expr>
    where
        V: Add<V, Output = AB::Expr>,
    {
        let mut elements = Vec::new();

        for (e1, e2) in self.0.iter().zip_eq(rhs.0.iter()) {
            elements.push(*e1 + *e2);
        }

        Extension(elements.into())
    }
}
