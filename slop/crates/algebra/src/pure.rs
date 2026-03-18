//! Abstract algebraic traits and constructions

use std::ops::{Add, Mul, Sub};

use p3_field::AbstractField;
use serde::{Deserialize, Serialize};

pub trait Module<R>: Add<R, Output = Self> + Sub<R, Output = Self> + Mul<R, Output = Self> {}

impl<R, E> Module<R> for E
where
    R: AbstractField,
    E: Add<R, Output = E> + Sub<R, Output = E> + Mul<R, Output = E>,
{
}

/// An abstract algebra over a field.
pub trait Algebra<R>: AbstractField + Module<R> {}

impl<R, E> Algebra<R> for E where E: AbstractField + Module<R> {}

/// A struct representing the `Dorroh extension` of a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Dorroh<F, E> {
    Constant(F),
    Element(E),
}

impl<F, E> From<F> for Dorroh<F, E> {
    fn from(value: F) -> Self {
        Self::Constant(value)
    }
}
