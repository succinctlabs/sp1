use std::ops::{Add, Div, Mul, Neg, Sub};

use p3_field::{
    extension::{BinomialExtensionField, BinomiallyExtendable},
    AbstractExtensionField, AbstractField, Field,
};
use sp1_derive::AlignedBorrow;

const DEGREE: usize = 4;

#[derive(AlignedBorrow, Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct BinomialExtension<T>(pub [T; DEGREE]);

impl<T> BinomialExtension<T> {
    pub fn from_base(b: T) -> Self
    where
        T: AbstractField,
    {
        let mut arr: [T; DEGREE] = core::array::from_fn(|_| T::zero());
        arr[0] = b;
        Self(arr)
    }

    pub const fn as_base_slice(&self) -> &[T] {
        &self.0
    }

    pub fn from<S: Into<T> + Clone>(from: BinomialExtension<S>) -> Self {
        BinomialExtension(core::array::from_fn(|i| from.0[i].clone().into()))
    }
}

impl<T: Add<Output = T> + Clone> Add for BinomialExtension<T> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(core::array::from_fn(|i| {
            self.0[i].clone() + rhs.0[i].clone()
        }))
    }
}

impl<T: Sub<Output = T> + Clone> Sub for BinomialExtension<T> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(core::array::from_fn(|i| {
            self.0[i].clone() - rhs.0[i].clone()
        }))
    }
}

impl<T: Add<Output = T> + Mul<Output = T> + AbstractField> Mul for BinomialExtension<T> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut result = [T::zero(), T::zero(), T::zero(), T::zero()];
        let w = T::from_canonical_u32(11);

        for i in 0..DEGREE {
            for j in 0..DEGREE {
                if i + j >= DEGREE {
                    result[i + j - DEGREE] += w.clone() * self.0[i].clone() * rhs.0[j].clone();
                } else {
                    result[i + j] += self.0[i].clone() * rhs.0[j].clone();
                }
            }
        }

        Self(result)
    }
}

impl<F> Div for BinomialExtension<F>
where
    F: BinomiallyExtendable<DEGREE>,
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
    F: BinomiallyExtendable<DEGREE>,
{
    pub fn inverse(&self) -> Self {
        let p3_ef = BinomialExtensionField::from_base_slice(&self.0);
        let p3_ef_inverse = p3_ef.inverse();
        Self(p3_ef_inverse.as_base_slice().try_into().unwrap())
    }
}

impl<T: AbstractField + Copy> Neg for BinomialExtension<T> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self([-self.0[0], -self.0[1], -self.0[2], -self.0[3]])
    }
}

impl<AF> From<BinomialExtensionField<AF, DEGREE>> for BinomialExtension<AF>
where
    AF: AbstractField + Copy,
    AF::F: BinomiallyExtendable<DEGREE>,
{
    fn from(value: BinomialExtensionField<AF, DEGREE>) -> Self {
        let arr: [AF; DEGREE] = value.as_base_slice().try_into().unwrap();
        Self(arr)
    }
}

impl<AF> From<BinomialExtension<AF>> for BinomialExtensionField<AF, DEGREE>
where
    AF: AbstractField + Copy,
    AF::F: BinomiallyExtendable<DEGREE>,
{
    fn from(value: BinomialExtension<AF>) -> Self {
        BinomialExtensionField::from_base_slice(&value.0)
    }
}

impl<T> IntoIterator for BinomialExtension<T> {
    type Item = T;
    type IntoIter = core::array::IntoIter<T, DEGREE>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
