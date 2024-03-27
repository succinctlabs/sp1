use p3_field::{
    extension::{BinomialExtensionField, BinomiallyExtendable},
    AbstractExtensionField, AbstractField,
};
use sp1_derive::AlignedBorrow;
use std::ops::{Add, Mul, Neg, Sub};

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
}

impl<T: Add<Output = T> + Clone> Add for BinomialExtension<T> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self([
            self.0[0].clone() + rhs.0[0].clone(),
            self.0[1].clone() + rhs.0[1].clone(),
            self.0[2].clone() + rhs.0[2].clone(),
            self.0[3].clone() + rhs.0[3].clone(),
        ])
    }
}

impl<T: Sub<Output = T> + Clone> Sub for BinomialExtension<T> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self([
            self.0[0].clone() - rhs.0[0].clone(),
            self.0[1].clone() - rhs.0[1].clone(),
            self.0[2].clone() - rhs.0[2].clone(),
            self.0[3].clone() - rhs.0[3].clone(),
        ])
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
