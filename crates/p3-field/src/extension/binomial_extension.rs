use alloc::format;
use alloc::string::ToString;
use core::array;
use core::fmt::{self, Debug, Display, Formatter};
use core::iter::{Product, Sum};
use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use itertools::Itertools;
use num_bigint::BigUint;
use rand::distributions::Standard;
use rand::prelude::Distribution;
use serde::{Deserialize, Serialize};

use super::{HasFrobenius, HasTwoAdicBionmialExtension};
use crate::extension::BinomiallyExtendable;
use crate::field::Field;
use crate::{
    field_to_array, AbstractExtensionField, AbstractField, ExtensionField, Packable, TwoAdicField,
};

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct BinomialExtensionField<AF, const D: usize> {
    #[serde(
        with = "p3_util::array_serialization",
        bound(serialize = "AF: Serialize", deserialize = "AF: Deserialize<'de>")
    )]
    pub(crate) value: [AF; D],
}

impl<AF: AbstractField, const D: usize> Default for BinomialExtensionField<AF, D> {
    fn default() -> Self {
        Self {
            value: array::from_fn(|_| AF::zero()),
        }
    }
}

impl<AF: AbstractField, const D: usize> From<AF> for BinomialExtensionField<AF, D> {
    fn from(x: AF) -> Self {
        Self {
            value: field_to_array::<AF, D>(x),
        }
    }
}

impl<F: BinomiallyExtendable<D>, const D: usize> Packable for BinomialExtensionField<F, D> {}

impl<F: BinomiallyExtendable<D>, const D: usize> ExtensionField<F>
    for BinomialExtensionField<F, D>
{
    type ExtensionPacking = BinomialExtensionField<F::Packing, D>;
}

impl<F: BinomiallyExtendable<D>, const D: usize> HasFrobenius<F> for BinomialExtensionField<F, D> {
    /// FrobeniusField automorphisms: x -> x^n, where n is the order of BaseField.
    fn frobenius(&self) -> Self {
        self.repeated_frobenius(1)
    }

    /// Repeated Frobenius automorphisms: x -> x^(n^count).
    ///
    /// Follows precomputation suggestion in Section 11.3.3 of the
    /// Handbook of Elliptic and Hyperelliptic Curve Cryptography.
    fn repeated_frobenius(&self, count: usize) -> Self {
        if count == 0 {
            return *self;
        } else if count >= D {
            // x |-> x^(n^D) is the identity, so x^(n^count) ==
            // x^(n^(count % D))
            return self.repeated_frobenius(count % D);
        }
        let arr: &[F] = self.as_base_slice();

        // z0 = DTH_ROOT^count = W^(k * count) where k = floor((n-1)/D)
        let mut z0 = F::dth_root();
        for _ in 1..count {
            z0 *= F::dth_root();
        }

        let mut res = [F::zero(); D];
        for (i, z) in z0.powers().take(D).enumerate() {
            res[i] = arr[i] * z;
        }

        Self::from_base_slice(&res)
    }

    /// Algorithm 11.3.4 in Handbook of Elliptic and Hyperelliptic Curve Cryptography.
    fn frobenius_inv(&self) -> Self {
        // Writing 'a' for self, we need to compute a^(r-1):
        // r = n^D-1/n-1 = n^(D-1)+n^(D-2)+...+n
        let mut f = Self::one();
        for _ in 1..D {
            f = (f * *self).frobenius();
        }

        // g = a^r is in the base field, so only compute that
        // coefficient rather than the full product.
        let a = self.value;
        let b = f.value;
        let mut g = F::zero();
        for i in 1..D {
            g += a[i] * b[D - i];
        }
        g *= F::w();
        g += a[0] * b[0];
        debug_assert_eq!(Self::from(g), *self * f);

        f * g.inverse()
    }
}

impl<AF, const D: usize> AbstractField for BinomialExtensionField<AF, D>
where
    AF: AbstractField,
    AF::F: BinomiallyExtendable<D>,
{
    type F = BinomialExtensionField<AF::F, D>;

    fn zero() -> Self {
        Self {
            value: field_to_array::<AF, D>(AF::zero()),
        }
    }
    fn one() -> Self {
        Self {
            value: field_to_array::<AF, D>(AF::one()),
        }
    }
    fn two() -> Self {
        Self {
            value: field_to_array::<AF, D>(AF::two()),
        }
    }
    fn neg_one() -> Self {
        Self {
            value: field_to_array::<AF, D>(AF::neg_one()),
        }
    }

    fn from_f(f: Self::F) -> Self {
        Self {
            value: f.value.map(AF::from_f),
        }
    }

    fn from_bool(b: bool) -> Self {
        AF::from_bool(b).into()
    }

    fn from_canonical_u8(n: u8) -> Self {
        AF::from_canonical_u8(n).into()
    }

    fn from_canonical_u16(n: u16) -> Self {
        AF::from_canonical_u16(n).into()
    }

    fn from_canonical_u32(n: u32) -> Self {
        AF::from_canonical_u32(n).into()
    }

    /// Convert from `u64`. Undefined behavior if the input is outside the canonical range.
    fn from_canonical_u64(n: u64) -> Self {
        AF::from_canonical_u64(n).into()
    }

    /// Convert from `usize`. Undefined behavior if the input is outside the canonical range.
    fn from_canonical_usize(n: usize) -> Self {
        AF::from_canonical_usize(n).into()
    }

    fn from_wrapped_u32(n: u32) -> Self {
        AF::from_wrapped_u32(n).into()
    }

    fn from_wrapped_u64(n: u64) -> Self {
        AF::from_wrapped_u64(n).into()
    }

    fn generator() -> Self {
        Self {
            value: AF::F::ext_generator().map(AF::from_f),
        }
    }

    #[inline(always)]
    fn square(&self) -> Self {
        match D {
            2 => {
                let a = self.value.clone();
                let mut res = Self::default();
                res.value[0] = a[0].square() + a[1].square() * AF::from_f(AF::F::w());
                res.value[1] = a[0].clone() * a[1].double();
                res
            }
            3 => Self {
                value: cubic_square(&self.value, AF::F::w())
                    .to_vec()
                    .try_into()
                    .unwrap(),
            },
            _ => <Self as Mul<Self>>::mul(self.clone(), self.clone()),
        }
    }
}

impl<F: BinomiallyExtendable<D>, const D: usize> Field for BinomialExtensionField<F, D> {
    type Packing = Self;

    fn try_inverse(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }

        match D {
            2 => Some(Self::from_base_slice(&qudratic_inv(&self.value, F::w()))),
            3 => Some(Self::from_base_slice(&cubic_inv(&self.value, F::w()))),
            _ => Some(self.frobenius_inv()),
        }
    }

    fn halve(&self) -> Self {
        Self {
            value: self.value.map(|x| x.halve()),
        }
    }

    fn order() -> BigUint {
        F::order().pow(D as u32)
    }
}

impl<F, const D: usize> Display for BinomialExtensionField<F, D>
where
    F: BinomiallyExtendable<D>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.is_zero() {
            write!(f, "0")
        } else {
            let str = self
                .value
                .iter()
                .enumerate()
                .filter(|(_, x)| !x.is_zero())
                .map(|(i, x)| match (i, x.is_one()) {
                    (0, _) => format!("{x}"),
                    (1, true) => "X".to_string(),
                    (1, false) => format!("{x} X"),
                    (_, true) => format!("X^{i}"),
                    (_, false) => format!("{x} X^{i}"),
                })
                .join(" + ");
            write!(f, "{}", str)
        }
    }
}

impl<AF, const D: usize> Neg for BinomialExtensionField<AF, D>
where
    AF: AbstractField,
    AF::F: BinomiallyExtendable<D>,
{
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        Self {
            value: self.value.map(AF::neg),
        }
    }
}

impl<AF, const D: usize> Add for BinomialExtensionField<AF, D>
where
    AF: AbstractField,
    AF::F: BinomiallyExtendable<D>,
{
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        let mut res = self.value;
        for (r, rhs_val) in res.iter_mut().zip(rhs.value) {
            *r += rhs_val;
        }
        Self { value: res }
    }
}

impl<AF, const D: usize> Add<AF> for BinomialExtensionField<AF, D>
where
    AF: AbstractField,
    AF::F: BinomiallyExtendable<D>,
{
    type Output = Self;

    #[inline]
    fn add(self, rhs: AF) -> Self {
        let mut res = self.value;
        res[0] += rhs;
        Self { value: res }
    }
}

impl<AF, const D: usize> AddAssign for BinomialExtensionField<AF, D>
where
    AF: AbstractField,
    AF::F: BinomiallyExtendable<D>,
{
    fn add_assign(&mut self, rhs: Self) {
        *self = self.clone() + rhs;
    }
}

impl<AF, const D: usize> AddAssign<AF> for BinomialExtensionField<AF, D>
where
    AF: AbstractField,
    AF::F: BinomiallyExtendable<D>,
{
    fn add_assign(&mut self, rhs: AF) {
        *self = self.clone() + rhs;
    }
}

impl<AF, const D: usize> Sum for BinomialExtensionField<AF, D>
where
    AF: AbstractField,
    AF::F: BinomiallyExtendable<D>,
{
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let zero = Self {
            value: field_to_array::<AF, D>(AF::zero()),
        };
        iter.fold(zero, |acc, x| acc + x)
    }
}

impl<AF, const D: usize> Sub for BinomialExtensionField<AF, D>
where
    AF: AbstractField,
    AF::F: BinomiallyExtendable<D>,
{
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        let mut res = self.value;
        for (r, rhs_val) in res.iter_mut().zip(rhs.value) {
            *r -= rhs_val;
        }
        Self { value: res }
    }
}

impl<AF, const D: usize> Sub<AF> for BinomialExtensionField<AF, D>
where
    AF: AbstractField,
    AF::F: BinomiallyExtendable<D>,
{
    type Output = Self;

    #[inline]
    fn sub(self, rhs: AF) -> Self {
        let mut res = self.value;
        res[0] -= rhs;
        Self { value: res }
    }
}

impl<AF, const D: usize> SubAssign for BinomialExtensionField<AF, D>
where
    AF: AbstractField,
    AF::F: BinomiallyExtendable<D>,
{
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.clone() - rhs;
    }
}

impl<AF, const D: usize> SubAssign<AF> for BinomialExtensionField<AF, D>
where
    AF: AbstractField,
    AF::F: BinomiallyExtendable<D>,
{
    #[inline]
    fn sub_assign(&mut self, rhs: AF) {
        *self = self.clone() - rhs;
    }
}

impl<AF, const D: usize> Mul for BinomialExtensionField<AF, D>
where
    AF: AbstractField,
    AF::F: BinomiallyExtendable<D>,
{
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        let a = self.value;
        let b = rhs.value;
        let w = AF::F::w();
        let w_af = AF::from_f(w);

        match D {
            2 => {
                let mut res = Self::default();
                res.value[0] = a[0].clone() * b[0].clone() + a[1].clone() * w_af * b[1].clone();
                res.value[1] = a[0].clone() * b[1].clone() + a[1].clone() * b[0].clone();
                res
            }
            3 => Self {
                value: cubic_mul(&a, &b, w).to_vec().try_into().unwrap(),
            },
            _ => {
                let mut res = Self::default();
                #[allow(clippy::needless_range_loop)]
                for i in 0..D {
                    for j in 0..D {
                        if i + j >= D {
                            res.value[i + j - D] += a[i].clone() * w_af.clone() * b[j].clone();
                        } else {
                            res.value[i + j] += a[i].clone() * b[j].clone();
                        }
                    }
                }
                res
            }
        }
    }
}

impl<AF, const D: usize> Mul<AF> for BinomialExtensionField<AF, D>
where
    AF: AbstractField,
    AF::F: BinomiallyExtendable<D>,
{
    type Output = Self;

    #[inline]
    fn mul(self, rhs: AF) -> Self {
        Self {
            value: self.value.map(|x| x * rhs.clone()),
        }
    }
}

impl<AF, const D: usize> Product for BinomialExtensionField<AF, D>
where
    AF: AbstractField,
    AF::F: BinomiallyExtendable<D>,
{
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        let one = Self {
            value: field_to_array::<AF, D>(AF::one()),
        };
        iter.fold(one, |acc, x| acc * x)
    }
}

impl<F, const D: usize> Div for BinomialExtensionField<F, D>
where
    F: BinomiallyExtendable<D>,
{
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.inverse()
    }
}

impl<F, const D: usize> DivAssign for BinomialExtensionField<F, D>
where
    F: BinomiallyExtendable<D>,
{
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

impl<AF, const D: usize> MulAssign for BinomialExtensionField<AF, D>
where
    AF: AbstractField,
    AF::F: BinomiallyExtendable<D>,
{
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.clone() * rhs;
    }
}

impl<AF, const D: usize> MulAssign<AF> for BinomialExtensionField<AF, D>
where
    AF: AbstractField,
    AF::F: BinomiallyExtendable<D>,
{
    fn mul_assign(&mut self, rhs: AF) {
        *self = self.clone() * rhs;
    }
}

impl<AF, const D: usize> AbstractExtensionField<AF> for BinomialExtensionField<AF, D>
where
    AF: AbstractField,
    AF::F: BinomiallyExtendable<D>,
{
    const D: usize = D;

    fn from_base(b: AF) -> Self {
        Self {
            value: field_to_array(b),
        }
    }

    fn from_base_slice(bs: &[AF]) -> Self {
        Self {
            value: bs.to_vec().try_into().expect("slice has wrong length"),
        }
    }

    #[inline]
    fn from_base_fn<F: FnMut(usize) -> AF>(f: F) -> Self {
        Self {
            value: array::from_fn(f),
        }
    }

    fn as_base_slice(&self) -> &[AF] {
        &self.value
    }
}

impl<F: BinomiallyExtendable<D>, const D: usize> Distribution<BinomialExtensionField<F, D>>
    for Standard
where
    Standard: Distribution<F>,
{
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> BinomialExtensionField<F, D> {
        let mut res = [F::zero(); D];
        for r in res.iter_mut() {
            *r = Standard.sample(rng);
        }
        BinomialExtensionField::<F, D>::from_base_slice(&res)
    }
}

impl<F: Field + HasTwoAdicBionmialExtension<D>, const D: usize> TwoAdicField
    for BinomialExtensionField<F, D>
{
    const TWO_ADICITY: usize = F::EXT_TWO_ADICITY;

    fn two_adic_generator(bits: usize) -> Self {
        Self {
            value: F::ext_two_adic_generator(bits),
        }
    }
}

///Section 11.3.6b in Handbook of Elliptic and Hyperelliptic Curve Cryptography.
#[inline]
fn qudratic_inv<F: Field>(a: &[F], w: F) -> [F; 2] {
    let scalar = (a[0].square() - w * a[1].square()).inverse();
    [a[0] * scalar, -a[1] * scalar]
}

/// Section 11.3.6b in Handbook of Elliptic and Hyperelliptic Curve Cryptography.
#[inline]
fn cubic_inv<F: Field>(a: &[F], w: F) -> [F; 3] {
    let a0_square = a[0].square();
    let a1_square = a[1].square();
    let a2_w = w * a[2];
    let a0_a1 = a[0] * a[1];

    // scalar = (a0^3+wa1^3+w^2a2^3-3wa0a1a2)^-1
    let scalar = (a0_square * a[0] + w * a[1] * a1_square + a2_w.square() * a[2]
        - (F::one() + F::two()) * a2_w * a0_a1)
        .inverse();

    //scalar*[a0^2-wa1a2, wa2^2-a0a1, a1^2-a0a2]
    [
        scalar * (a0_square - a[1] * a2_w),
        scalar * (a2_w * a[2] - a0_a1),
        scalar * (a1_square - a[0] * a[2]),
    ]
}

/// karatsuba multiplication for cubic extension field
#[inline]
fn cubic_mul<AF: AbstractField>(a: &[AF], b: &[AF], w: AF::F) -> [AF; 3] {
    let a0_b0 = a[0].clone() * b[0].clone();
    let a1_b1 = a[1].clone() * b[1].clone();
    let a2_b2 = a[2].clone() * b[2].clone();

    let c0 = a0_b0.clone()
        + ((a[1].clone() + a[2].clone()) * (b[1].clone() + b[2].clone())
            - a1_b1.clone()
            - a2_b2.clone())
            * AF::from_f(w);
    let c1 = (a[0].clone() + a[1].clone()) * (b[0].clone() + b[1].clone())
        - a0_b0.clone()
        - a1_b1.clone()
        + a2_b2.clone() * AF::from_f(w);
    let c2 = (a[0].clone() + a[2].clone()) * (b[0].clone() + b[2].clone()) - a0_b0 - a2_b2 + a1_b1;

    [c0, c1, c2]
}

/// Section 11.3.6a in Handbook of Elliptic and Hyperelliptic Curve Cryptography.
#[inline]
fn cubic_square<AF: AbstractField>(a: &[AF], w: AF::F) -> [AF; 3] {
    let w_a2 = a[2].clone() * AF::from_f(w);

    let c0 = a[0].square() + (a[1].clone() * w_a2.clone()).double();
    let c1 = w_a2 * a[2].clone() + (a[0].clone() * a[1].clone()).double();
    let c2 = a[1].square() + (a[0].clone() * a[2].clone()).double();

    [c0, c1, c2]
}
