use std::ops::{Add, Div, Mul, Neg, Sub};

use p3_field::{
    extension::{BinomialExtensionField, BinomiallyExtendable},
    AbstractExtensionField, AbstractField, Field,
};
use sp1_derive::AlignedBorrow;

const D: usize = 4;

/// A binomial extension element represented over a generic type `T`.
#[derive(AlignedBorrow, Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct BinomialExtension<T>(pub [T; D]);

impl<T> BinomialExtension<T> {
    /// Creates a new binomial extension element from a base element.
    pub fn from_base(b: T) -> Self
    where
        T: AbstractField,
    {
        let mut arr: [T; D] = core::array::from_fn(|_| T::zero());
        arr[0] = b;
        Self(arr)
    }

    /// Returns a reference to the underlying slice.
    pub const fn as_base_slice(&self) -> &[T] {
        &self.0
    }

    /// Creates a new binomial extension element from a binomial extension element.
    #[allow(clippy::needless_pass_by_value)]
    pub fn from<S: Into<T> + Clone>(from: BinomialExtension<S>) -> Self {
        BinomialExtension(core::array::from_fn(|i| from.0[i].clone().into()))
    }
}

impl<T: Add<Output = T> + Clone> Add for BinomialExtension<T> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(core::array::from_fn(|i| self.0[i].clone() + rhs.0[i].clone()))
    }
}

impl<T: Sub<Output = T> + Clone> Sub for BinomialExtension<T> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(core::array::from_fn(|i| self.0[i].clone() - rhs.0[i].clone()))
    }
}

impl<T: Add<Output = T> + Mul<Output = T> + AbstractField> Mul for BinomialExtension<T> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut result = [T::zero(), T::zero(), T::zero(), T::zero()];
        let w = T::from_canonical_u32(11);

        for i in 0..D {
            for j in 0..D {
                if i + j >= D {
                    result[i + j - D] = result[i + j - D].clone()
                        + w.clone() * self.0[i].clone() * rhs.0[j].clone();
                } else {
                    result[i + j] = result[i + j].clone() + self.0[i].clone() * rhs.0[j].clone();
                }
            }
        }

        Self(result)
    }
}

impl<F> Div for BinomialExtension<F>
where
    F: BinomiallyExtendable<D>,
{
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        let p3_ef_lhs = BinomialExtensionField::from_base_slice(&self.0);
        let p3_ef_rhs = BinomialExtensionField::from_base_slice(&rhs.0);
        let p3_ef_result = p3_ef_lhs / p3_ef_rhs;
        Self(p3_ef_result.as_base_slice().try_into().unwrap())
    }
}

impl<F> BinomialExtension<F>
where
    F: BinomiallyExtendable<4>,
{
    /// Returns the multiplicative inverse of the element.
    #[must_use]
    pub fn inverse(&self) -> Self {
        let p3_ef = BinomialExtensionField::from_base_slice(&self.0);
        let p3_ef_inverse = p3_ef.inverse();
        Self(p3_ef_inverse.as_base_slice().try_into().unwrap())
    }

    /// Returns the multiplicative inverse of the element, if it exists.
    #[must_use]
    pub fn try_inverse(&self) -> Option<Self> {
        let p3_ef = BinomialExtensionField::from_base_slice(&self.0);
        let p3_ef_inverse = p3_ef.try_inverse()?;
        Some(Self(p3_ef_inverse.as_base_slice().try_into().unwrap()))
    }
}

impl<T: AbstractField + Copy> Neg for BinomialExtension<T> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self([-self.0[0], -self.0[1], -self.0[2], -self.0[3]])
    }
}

impl<AF> From<BinomialExtensionField<AF, D>> for BinomialExtension<AF>
where
    AF: AbstractField + Copy,
    AF::F: BinomiallyExtendable<D>,
{
    fn from(value: BinomialExtensionField<AF, D>) -> Self {
        let arr: [AF; D] = value.as_base_slice().try_into().unwrap();
        Self(arr)
    }
}

impl<AF> From<BinomialExtension<AF>> for BinomialExtensionField<AF, D>
where
    AF: AbstractField + Copy,
    AF::F: BinomiallyExtendable<D>,
{
    fn from(value: BinomialExtension<AF>) -> Self {
        BinomialExtensionField::from_base_slice(&value.0)
    }
}

impl<T> IntoIterator for BinomialExtension<T> {
    type Item = T;
    type IntoIter = core::array::IntoIter<T, D>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
