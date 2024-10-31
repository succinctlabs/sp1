use num_bigint::BigUint;
use p3_field::{AbstractExtensionField, AbstractField, ExtensionField, Field, Packable};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::iter::{Product, Sum};
use std::ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign};

/// A septic extension with an irreducible polynomial `z^7 - 2z - 5`.
///
/// The field can be constructed as `F_{p^7} = F_p[z]/(z^7 - 2z - 5)`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SepticExtension<F>([F; 7]);

impl<F: AbstractField> AbstractField for SepticExtension<F> {
    type F = SepticExtension<F::F>;

    fn zero() -> Self {
        SepticExtension([
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
        ])
    }

    fn one() -> Self {
        SepticExtension([
            F::one(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
        ])
    }

    fn two() -> Self {
        SepticExtension([
            F::two(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
        ])
    }

    fn neg_one() -> Self {
        SepticExtension([
            F::neg_one(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
        ])
    }

    fn from_f(f: Self::F) -> Self {
        SepticExtension([
            F::from_f(f.0[0]),
            F::from_f(f.0[1]),
            F::from_f(f.0[2]),
            F::from_f(f.0[3]),
            F::from_f(f.0[4]),
            F::from_f(f.0[5]),
            F::from_f(f.0[6]),
        ])
    }

    fn from_bool(b: bool) -> Self {
        SepticExtension([
            F::from_bool(b),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
            F::zero(),
        ])
    }

    fn from_canonical_u8(n: u8) -> Self {
        SepticExtension([
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
        SepticExtension([
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
        SepticExtension([
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
        SepticExtension([
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
        SepticExtension([
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
        SepticExtension([
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
        SepticExtension([
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

impl<F: Field> Field for SepticExtension<F> {
    type Packing = Self;

    fn try_inverse(&self) -> Option<Self> {
        todo!()
    }

    fn order() -> BigUint {
        todo!()
    }
}

impl<F: AbstractField> AbstractExtensionField<F> for SepticExtension<F> {
    const D: usize = 7;

    fn from_base(b: F) -> Self {
        SepticExtension([b, F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero()])
    }

    fn from_base_slice(bs: &[F]) -> Self {
        SepticExtension([
            bs[0].clone(),
            bs[1].clone(),
            bs[2].clone(),
            bs[3].clone(),
            bs[4].clone(),
            bs[5].clone(),
            bs[6].clone(),
        ])
    }

    fn from_base_fn<G: FnMut(usize) -> F>(_: G) -> Self {
        todo!()
    }

    fn as_base_slice(&self) -> &[F] {
        self.0.as_slice()
    }
}

impl<F: Field> ExtensionField<F> for SepticExtension<F> {
    type ExtensionPacking = SepticExtension<F::Packing>;
}

impl<F: Field> Packable for SepticExtension<F> {}

impl<F: AbstractField> Add for SepticExtension<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut res = self.0;
        for (r, rhs_val) in res.iter_mut().zip(rhs.0) {
            *r += rhs_val;
        }
        Self(res)
    }
}

impl<F: AbstractField> AddAssign for SepticExtension<F> {
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

impl<F: AbstractField> Sub for SepticExtension<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let mut res = self.0;
        for (r, rhs_val) in res.iter_mut().zip(rhs.0) {
            *r -= rhs_val;
        }
        Self(res)
    }
}

impl<F: AbstractField> SubAssign for SepticExtension<F> {
    fn sub_assign(&mut self, rhs: Self) {
        self.0[0] -= rhs.0[0].clone();
    }
}

impl<F: AbstractField> Neg for SepticExtension<F> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut res = self.0;
        for r in res.iter_mut() {
            *r = -r.clone();
        }
        Self(res)
    }
}

impl<F: AbstractField> Mul for SepticExtension<F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        todo!()
    }
}

impl<F: AbstractField> MulAssign for SepticExtension<F> {
    fn mul_assign(&mut self, rhs: Self) {
        todo!()
    }
}

impl<F: AbstractField> Product for SepticExtension<F> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        todo!()
    }
}

impl<F: AbstractField> Sum for SepticExtension<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        todo!()
    }
}

impl<F: AbstractField> From<F> for SepticExtension<F> {
    fn from(f: F) -> Self {
        SepticExtension([f, F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero()])
    }
}

impl<F: AbstractField> Add<F> for SepticExtension<F> {
    type Output = Self;

    fn add(self, rhs: F) -> Self::Output {
        SepticExtension([
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

impl<F: AbstractField> AddAssign<F> for SepticExtension<F> {
    fn add_assign(&mut self, rhs: F) {
        self.0[0] += rhs;
    }
}

impl<F: AbstractField> Sub<F> for SepticExtension<F> {
    type Output = Self;

    fn sub(self, rhs: F) -> Self::Output {
        self + (-rhs)
    }
}

impl<F: AbstractField> SubAssign<F> for SepticExtension<F> {
    fn sub_assign(&mut self, rhs: F) {
        self.0[0] -= rhs;
    }
}

impl<F: AbstractField> Mul<F> for SepticExtension<F> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self::Output {
        todo!()
    }
}

impl<F: AbstractField> MulAssign<F> for SepticExtension<F> {
    fn mul_assign(&mut self, rhs: F) {
        todo!()
    }
}

impl<F: AbstractField> Div for SepticExtension<F> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        todo!()
    }
}

impl<F: AbstractField> Display for SepticExtension<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}
