use alloc::rc::Rc;
use core::fmt::Debug;
use core::fmt::Display;
use core::fmt::Formatter;
use core::iter::{Product, Sum};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use p3_field::{AbstractField, Field};

use super::variable::SymbolicVariable;

/// An expression over `SymbolicVariable`s.
#[derive(Clone, Debug)]
pub enum SymbolicExpression<F: Field> {
    Variable(SymbolicVariable<F>),
    IsFirstRow,
    IsLastRow,
    IsTransition,
    Constant(F),
    Add(Rc<Self>, Rc<Self>),
    Sub(Rc<Self>, Rc<Self>),
    Neg(Rc<Self>),
    Mul(Rc<Self>, Rc<Self>),
}

impl<F: Field> SymbolicExpression<F> {
    /// Returns the multiple of `n` (the trace length) in this expression's degree.
    pub(crate) fn degree_multiple(&self) -> usize {
        match self {
            SymbolicExpression::Variable(_) => 1,
            SymbolicExpression::IsFirstRow => 1,
            SymbolicExpression::IsLastRow => 1,
            SymbolicExpression::IsTransition => 0,
            SymbolicExpression::Constant(_) => 0,
            SymbolicExpression::Add(x, y) => x.degree_multiple().max(y.degree_multiple()),
            SymbolicExpression::Sub(x, y) => x.degree_multiple().max(y.degree_multiple()),
            SymbolicExpression::Neg(x) => x.degree_multiple(),
            SymbolicExpression::Mul(x, y) => x.degree_multiple() + y.degree_multiple(),
        }
    }
}

impl<F: Field> Default for SymbolicExpression<F> {
    fn default() -> Self {
        Self::Constant(F::zero())
    }
}

impl<F: Field> From<F> for SymbolicExpression<F> {
    fn from(value: F) -> Self {
        Self::Constant(value)
    }
}

impl<F: Field> AbstractField for SymbolicExpression<F> {
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

    #[inline]
    fn from_f(f: Self::F) -> Self {
        f.into()
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

impl<F: Field> Add for SymbolicExpression<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self::Add(Rc::new(self), Rc::new(rhs))
    }
}

impl<F: Field> Add<F> for SymbolicExpression<F> {
    type Output = Self;

    fn add(self, rhs: F) -> Self {
        self + Self::from(rhs)
    }
}

impl<F: Field> AddAssign for SymbolicExpression<F> {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.clone() + rhs;
    }
}

impl<F: Field> AddAssign<F> for SymbolicExpression<F> {
    fn add_assign(&mut self, rhs: F) {
        *self += Self::from(rhs);
    }
}

impl<F: Field> Sum for SymbolicExpression<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|x, y| x + y).unwrap_or(Self::zero())
    }
}

impl<F: Field> Sum<F> for SymbolicExpression<F> {
    fn sum<I: Iterator<Item = F>>(iter: I) -> Self {
        iter.map(|x| Self::from(x)).sum()
    }
}

impl<F: Field> Sub for SymbolicExpression<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self::Sub(Rc::new(self), Rc::new(rhs))
    }
}

impl<F: Field> Sub<F> for SymbolicExpression<F> {
    type Output = Self;

    fn sub(self, rhs: F) -> Self {
        self - Self::from(rhs)
    }
}

impl<F: Field> SubAssign for SymbolicExpression<F> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.clone() - rhs;
    }
}

impl<F: Field> SubAssign<F> for SymbolicExpression<F> {
    fn sub_assign(&mut self, rhs: F) {
        *self -= Self::from(rhs);
    }
}

impl<F: Field> Neg for SymbolicExpression<F> {
    type Output = Self;

    fn neg(self) -> Self {
        Self::Neg(Rc::new(self))
    }
}

impl<F: Field> Mul for SymbolicExpression<F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Self::Mul(Rc::new(self), Rc::new(rhs))
    }
}

impl<F: Field> Mul<F> for SymbolicExpression<F> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self {
        self * Self::from(rhs)
    }
}

impl<F: Field> MulAssign for SymbolicExpression<F> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.clone() * rhs;
    }
}

impl<F: Field> MulAssign<F> for SymbolicExpression<F> {
    fn mul_assign(&mut self, rhs: F) {
        *self *= Self::from(rhs);
    }
}

impl<F: Field> Product for SymbolicExpression<F> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|x, y| x * y).unwrap_or(Self::one())
    }
}

impl<F: Field> Product<F> for SymbolicExpression<F> {
    fn product<I: Iterator<Item = F>>(iter: I) -> Self {
        iter.map(|x| Self::from(x)).product()
    }
}

impl<F: Field> Display for SymbolicExpression<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SymbolicExpression::Variable(v) => write!(f, "{}", v),
            SymbolicExpression::IsFirstRow => write!(f, "IsFirstRow"),
            SymbolicExpression::IsLastRow => write!(f, "IsLastRow"),
            SymbolicExpression::IsTransition => write!(f, "IsTransition"),
            SymbolicExpression::Constant(c) => write!(f, "{}", c),
            SymbolicExpression::Add(x, y) => write!(f, "({} + {})", x, y),
            SymbolicExpression::Sub(x, y) => write!(f, "({} - {})", x, y),
            SymbolicExpression::Neg(x) => write!(f, "-{}", x),
            SymbolicExpression::Mul(x, y) => write!(f, "({} * {})", x, y),
        }
    }
}
