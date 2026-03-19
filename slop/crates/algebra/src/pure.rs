//! Abstract algebraic traits and constructions

use std::{
    fmt::Debug,
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use p3_field::{AbstractField, Field};
use serde::{Deserialize, Serialize};

pub trait Module<R>:
    Clone + Add<R, Output = Self> + Sub<R, Output = Self> + Mul<R, Output = Self> + Neg<Output = Self>
{
}

impl<R, E> Module<R> for E
where
    R: AbstractField,
    E: Clone + Add<R, Output = E> + Sub<R, Output = E> + Mul<R, Output = E> + Neg<Output = E>,
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

impl<F: Default, E> Default for Dorroh<F, E> {
    fn default() -> Self {
        Self::Constant(F::default())
    }
}

impl<F, E> Add for Dorroh<F, E>
where
    F: Field,
    E: Module<F> + Add<Output = E>,
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        match (self, rhs) {
            (Self::Constant(a), Self::Constant(b)) => Self::Constant(a + b),
            (Self::Element(a), Self::Element(b)) => Self::Element(a + b),
            (Self::Constant(a), Self::Element(b)) => Self::Element(b + a),
            (Self::Element(a), Self::Constant(b)) => Self::Element(a + b),
        }
    }
}

impl<F, E> AddAssign for Dorroh<F, E>
where
    F: Field,
    E: Module<F> + Add<Output = E>,
{
    fn add_assign(&mut self, rhs: Self) {
        *self = self.clone() + rhs;
    }
}

impl<F, E> Sub for Dorroh<F, E>
where
    F: Field,
    E: Module<F> + Sub<Output = E>,
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        match (self, rhs) {
            (Self::Constant(a), Self::Constant(b)) => Self::Constant(a - b),
            (Self::Element(a), Self::Element(b)) => Self::Element(a - b),
            (Self::Constant(a), Self::Element(b)) => Self::Element(-b + a),
            (Self::Element(a), Self::Constant(b)) => Self::Element(a - b),
        }
    }
}

impl<F, E> SubAssign for Dorroh<F, E>
where
    F: Field,
    E: Module<F> + Sub<Output = E>,
{
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.clone() - rhs;
    }
}

impl<F, E> Neg for Dorroh<F, E>
where
    F: Field,
    E: Module<F>,
{
    type Output = Self;

    fn neg(self) -> Self {
        match self {
            Self::Constant(a) => Self::Constant(-a),
            Self::Element(a) => Self::Element(-a),
        }
    }
}

impl<F, E> Mul for Dorroh<F, E>
where
    F: Field,
    E: Module<F> + Mul<Output = E>,
{
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        match (self, rhs) {
            (Self::Constant(a), Self::Constant(b)) => Self::Constant(a * b),
            (Self::Element(a), Self::Element(b)) => Self::Element(a * b),
            (Self::Constant(a), Self::Element(b)) => Self::Element(b * a),
            (Self::Element(a), Self::Constant(b)) => Self::Element(a * b),
        }
    }
}

impl<F, E> MulAssign for Dorroh<F, E>
where
    F: Field,
    E: Module<F> + Mul<Output = E>,
{
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.clone() * rhs;
    }
}

impl<F, E> Sum for Dorroh<F, E>
where
    F: Field,
    E: Module<F> + Mul<Output = E> + Add<Output = E> + Sub<Output = E> + Debug,
{
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |acc, x| acc + x)
    }
}

impl<F, E> Product for Dorroh<F, E>
where
    F: Field,
    E: Module<F> + Mul<Output = E> + Add<Output = E> + Sub<Output = E> + Debug,
{
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::one(), |acc, x| acc * x)
    }
}

impl<F, E> Add<F> for Dorroh<F, E>
where
    F: Field,
    E: Module<F>,
{
    type Output = Self;

    fn add(self, rhs: F) -> Self {
        match self {
            Self::Constant(a) => Self::Constant(a + rhs),
            Self::Element(a) => Self::Element(a + rhs),
        }
    }
}

impl<F, E> Sub<F> for Dorroh<F, E>
where
    F: Field,
    E: Module<F>,
{
    type Output = Self;

    fn sub(self, rhs: F) -> Self {
        match self {
            Self::Constant(a) => Self::Constant(a - rhs),
            Self::Element(a) => Self::Element(a - rhs),
        }
    }
}

impl<F, E> Mul<F> for Dorroh<F, E>
where
    F: Field,
    E: Module<F>,
{
    type Output = Self;

    fn mul(self, rhs: F) -> Self {
        match self {
            Self::Constant(a) => Self::Constant(a * rhs),
            Self::Element(a) => Self::Element(a * rhs),
        }
    }
}

impl<F, E> AbstractField for Dorroh<F, E>
where
    F: Field,
    E: Module<F> + Mul<Output = E> + Add<Output = E> + Sub<Output = E> + Debug,
{
    type F = F;

    fn zero() -> Self {
        Self::Constant(F::zero())
    }

    fn one() -> Self {
        Self::Constant(F::one())
    }

    fn two() -> Self {
        Self::Constant(F::two())
    }

    fn neg_one() -> Self {
        Self::Constant(F::neg_one())
    }

    fn from_f(f: Self::F) -> Self {
        Self::Constant(f)
    }

    fn from_bool(b: bool) -> Self {
        Self::Constant(F::from_bool(b))
    }

    fn from_canonical_u8(n: u8) -> Self {
        Self::Constant(F::from_canonical_u8(n))
    }

    fn from_canonical_u16(n: u16) -> Self {
        Self::Constant(F::from_canonical_u16(n))
    }

    fn from_canonical_u32(n: u32) -> Self {
        Self::Constant(F::from_canonical_u32(n))
    }

    fn from_canonical_u64(n: u64) -> Self {
        Self::Constant(F::from_canonical_u64(n))
    }

    fn from_canonical_usize(n: usize) -> Self {
        Self::Constant(F::from_canonical_usize(n))
    }

    fn from_wrapped_u32(n: u32) -> Self {
        Self::Constant(F::from_wrapped_u32(n))
    }

    fn from_wrapped_u64(n: u64) -> Self {
        Self::Constant(F::from_wrapped_u64(n))
    }

    fn generator() -> Self {
        Self::Constant(F::generator())
    }
}
