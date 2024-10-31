use num_bigint::BigUint;
use p3_field::{AbstractExtensionField, AbstractField, ExtensionField, Field, Packable};
use serde::{Deserialize, Serialize};
use std::iter::{Product, Sum};
use std::ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign};

use std::fmt::Display;
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EF7<F>([F; 7]);

impl<F: AbstractField> Add for EF7<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut res = self.0;
        for (r, rhs_val) in res.iter_mut().zip(rhs.0) {
            *r += rhs_val;
        }
        Self(res)
    }
}

impl<F: AbstractField> AddAssign for EF7<F> {
    fn add_assign(&mut self, rhs: Self) {
        self.0[0] += rhs.0[0].clone();
        self.0[1] += rhs.0[1].clone();
        self.0[2] += rhs.0[2].clone();
        self.0[3] += rhs.0[3].clone();
        self.0[4] += rhs.0[4].clone();
        self.0[5] += rhs.0[5].clone();
        self.0[6] += rhs.0[6].clone();
    }
}

impl<F: AbstractField> Sub for EF7<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let mut res = self.0;
        for (r, rhs_val) in res.iter_mut().zip(rhs.0) {
            *r -= rhs_val;
        }
        Self(res)
    }
}

impl<F: AbstractField> SubAssign for EF7<F> {
    fn sub_assign(&mut self, rhs: Self) {
        self.0[0] -= rhs.0[0].clone();
    }
}

impl<F: AbstractField> Neg for EF7<F> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut res = self.0;
        for r in res.iter_mut() {
            *r = -r.clone();
        }
        Self(res)
    }
}

impl<F: AbstractField> Mul for EF7<F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        todo!()
    }
}

impl<F: AbstractField> MulAssign for EF7<F> {
    fn mul_assign(&mut self, rhs: Self) {
        todo!()
    }
}

impl<F: AbstractField> Product for EF7<F> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        todo!()
    }
}

impl<F: AbstractField> Sum for EF7<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        todo!()
    }
}

impl<F: AbstractField> AbstractField for EF7<F> {
    type F = EF7<F::F>;

    fn zero() -> Self {
        EF7([F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero()])
    }

    fn one() -> Self {
        EF7([F::one(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero()])
    }

    fn two() -> Self {
        EF7([F::two(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero()])
    }

    fn neg_one() -> Self {
        EF7([F::neg_one(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero()])
    }

    fn from_f(f: Self::F) -> Self {
        todo!()
    }

    fn from_bool(b: bool) -> Self {
        EF7([F::from_bool(b), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero()])
    }

    fn from_canonical_u8(n: u8) -> Self {
        EF7([
            F::from_canonical_u8(n),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
        ])
    }

    fn from_canonical_u16(n: u16) -> Self {
        EF7([
            F::from_canonical_u16(n),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
        ])
    }

    fn from_canonical_u32(n: u32) -> Self {
        EF7([
            F::from_canonical_u32(n),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
        ])
    }

    fn from_canonical_u64(n: u64) -> Self {
        EF7([
            F::from_canonical_u64(n),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
        ])
    }

    fn from_canonical_usize(n: usize) -> Self {
        EF7([
            F::from_canonical_usize(n),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
        ])
    }

    fn from_wrapped_u32(n: u32) -> Self {
        EF7([
            F::from_wrapped_u32(n),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
        ])
    }

    fn from_wrapped_u64(n: u64) -> Self {
        EF7([
            F::from_wrapped_u64(n),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
        ])
    }

    fn generator() -> Self {
        todo!()
    }
}

impl<F: AbstractField> AbstractExtensionField<F> for EF7<F> {
    const D: usize = 7;

    fn from_base(b: F) -> Self {
        EF7([b, F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero()])
    }

    fn from_base_slice(bs: &[F]) -> Self {
        EF7([
            bs[0].clone(),
            bs[1].clone(),
            bs[2].clone(),
            bs[3].clone(),
            bs[4].clone(),
            bs[5].clone(),
            F::zero(),
            // bs[6].clone(),
        ])
    }

    fn from_base_fn<G: FnMut(usize) -> F>(f: G) -> Self {
        // TODO: FIX
        Self::zero()
    }

    fn as_base_slice(&self) -> &[F] {
        self.0.as_slice()
    }
}

impl<F: AbstractField> From<F> for EF7<F> {
    fn from(f: F) -> Self {
        EF7([f, F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero()])
    }
}

impl<F: AbstractField> Add<F> for EF7<F> {
    type Output = Self;

    fn add(self, rhs: F) -> Self::Output {
        EF7([
            self.0[0].clone() + rhs,
            self.0[1].clone(),
            self.0[2].clone(),
            self.0[3].clone(),
            self.0[4].clone(),
            self.0[5].clone(),
            self.0[6].clone(),
        ])
    }
}

impl<F: AbstractField> AddAssign<F> for EF7<F> {
    fn add_assign(&mut self, rhs: F) {
        self.0[0] += rhs;
    }
}

impl<F: AbstractField> Sub<F> for EF7<F> {
    type Output = Self;

    fn sub(self, rhs: F) -> Self::Output {
        self + (-rhs)
    }
}

impl<F: AbstractField> SubAssign<F> for EF7<F> {
    fn sub_assign(&mut self, rhs: F) {
        self.0[0] -= rhs;
    }
}

impl<F: AbstractField> Mul<F> for EF7<F> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self::Output {
        todo!()
    }
}

impl<F: AbstractField> MulAssign<F> for EF7<F> {
    fn mul_assign(&mut self, rhs: F) {
        todo!()
    }
}

impl<F: AbstractField> Div for EF7<F> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        todo!()
    }
}

impl<F: Field> Field for EF7<F> {
    type Packing = Self;

    fn try_inverse(&self) -> Option<Self> {
        todo!()
    }

    fn order() -> BigUint {
        todo!()
    }
}

impl<F: AbstractField> Display for EF7<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<F: Field> Packable for EF7<F> {}

impl<F: Field> ExtensionField<F> for EF7<F> {
    type ExtensionPacking = EF7<F::Packing>;
}
