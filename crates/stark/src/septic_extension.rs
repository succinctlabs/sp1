use num_bigint::BigUint;
use num_traits::One;
use p3_field::{AbstractExtensionField, AbstractField, ExtensionField, Field, Packable};
use serde::{Deserialize, Serialize};
use std::array;
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
        SepticExtension([F::two(), F::one(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero()])
    }
}

impl<F: Field> Field for SepticExtension<F> {
    type Packing = Self;

    fn try_inverse(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        Some(self.inv())
    }

    fn order() -> BigUint {
        F::order().pow(7)
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

    fn from_base_fn<G: FnMut(usize) -> F>(f: G) -> Self {
        Self(array::from_fn(f))
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
        let mut res = [F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero()];
        for i in 0..7 {
            for j in 0..7 {
                let k = i + j;
                if k < 7 {
                    res[k] += self.0[i].clone() * rhs.0[j].clone();
                } else {
                    let rem = k % 7;
                    let prod = self.0[i].clone() * rhs.0[j].clone();
                    res[rem] += prod.clone() * F::from_canonical_u32(5);
                    res[rem + 1] += prod.clone() * F::from_canonical_u32(2);
                }
            }
        }
        Self(res)
    }
}

impl<F: AbstractField> MulAssign for SepticExtension<F> {
    fn mul_assign(&mut self, rhs: Self) {
        let res = self.clone() * rhs;
        *self = res;
    }
}

impl<F: AbstractField> Product for SepticExtension<F> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        let one = Self::one();
        iter.fold(one, |acc, x| acc * x)
    }
}

impl<F: AbstractField> Sum for SepticExtension<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let zero = Self::zero();
        iter.fold(zero, |acc, x| acc + x)
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
        SepticExtension([
            self.0[0].clone() * rhs.clone(),
            self.0[1].clone() * rhs.clone(),
            self.0[2].clone() * rhs.clone(),
            self.0[3].clone() * rhs.clone(),
            self.0[4].clone() * rhs.clone(),
            self.0[5].clone() * rhs.clone(),
            self.0[6].clone() * rhs.clone(),
        ])
    }
}

impl<F: AbstractField> MulAssign<F> for SepticExtension<F> {
    fn mul_assign(&mut self, rhs: F) {
        for i in 0..7 {
            self.0[i] *= rhs.clone();
        }
    }
}

impl<F: Field> Div for SepticExtension<F> {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.inverse()
    }
}

impl<F: AbstractField> Display for SepticExtension<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<F: Field> SepticExtension<F> {
    fn z_pow_p(index: u32) -> Self {
        // The constants written below are specifically for the BabyBear field.
        debug_assert_eq!(F::order(), BigUint::from(2013265921u32));
        if index == 0 {
            return Self::one();
        }
        if index == 1 {
            return SepticExtension([
                F::from_canonical_u32(954599710),
                F::from_canonical_u32(1359279693),
                F::from_canonical_u32(566669999),
                F::from_canonical_u32(1982781815),
                F::from_canonical_u32(1735718361),
                F::from_canonical_u32(1174868538),
                F::from_canonical_u32(1120871770),
            ]);
        }
        if index == 2 {
            return SepticExtension([
                F::from_canonical_u32(862825265),
                F::from_canonical_u32(597046311),
                F::from_canonical_u32(978840770),
                F::from_canonical_u32(1790138282),
                F::from_canonical_u32(1044777201),
                F::from_canonical_u32(835869808),
                F::from_canonical_u32(1342179023),
            ]);
        }
        if index == 3 {
            return SepticExtension([
                F::from_canonical_u32(596273169),
                F::from_canonical_u32(658837454),
                F::from_canonical_u32(1515468261),
                F::from_canonical_u32(367059247),
                F::from_canonical_u32(781278880),
                F::from_canonical_u32(1544222616),
                F::from_canonical_u32(155490465),
            ]);
        }
        if index == 4 {
            return SepticExtension([
                F::from_canonical_u32(557608863),
                F::from_canonical_u32(1173670028),
                F::from_canonical_u32(1749546888),
                F::from_canonical_u32(1086464137),
                F::from_canonical_u32(803900099),
                F::from_canonical_u32(1288818584),
                F::from_canonical_u32(1184677604),
            ]);
        }
        if index == 5 {
            return SepticExtension([
                F::from_canonical_u32(763416381),
                F::from_canonical_u32(1252567168),
                F::from_canonical_u32(628856225),
                F::from_canonical_u32(1771903394),
                F::from_canonical_u32(650712211),
                F::from_canonical_u32(19417363),
                F::from_canonical_u32(57990258),
            ]);
        }
        if index == 6 {
            return SepticExtension([
                F::from_canonical_u32(1734711039),
                F::from_canonical_u32(1749813853),
                F::from_canonical_u32(1227235221),
                F::from_canonical_u32(1707730636),
                F::from_canonical_u32(424560395),
                F::from_canonical_u32(1007029514),
                F::from_canonical_u32(498034669),
            ]);
        }
        unreachable!();
    }

    #[must_use]
    fn frobenius(&self) -> Self {
        let mut result = Self::zero();
        result += self.0[0];
        result += Self::z_pow_p(1) * self.0[1];
        result += Self::z_pow_p(2) * self.0[2];
        result += Self::z_pow_p(3) * self.0[3];
        result += Self::z_pow_p(4) * self.0[4];
        result += Self::z_pow_p(5) * self.0[5];
        result += Self::z_pow_p(6) * self.0[6];
        result
    }

    #[must_use]
    fn pow_r_1(&self) -> Self {
        let mut vp = self.frobenius();
        let mut result = vp;
        for _ in 2..7 {
            vp = vp.frobenius();
            result *= vp;
        }
        result
    }

    #[must_use]
    fn inv(&self) -> Self {
        let pow_r_1 = self.pow_r_1();
        let pow_r = pow_r_1 * *self;
        pow_r_1 * pow_r.0[0].inverse()
    }

    /// Returns whether or not a septic field extension element is a square.
    pub fn is_square(&self) -> bool {
        let pow_r_1 = self.pow_r_1();
        let pow_r = pow_r_1 * *self;
        let exp = (F::order() - BigUint::one()) / BigUint::from(2u8);
        let exp = exp.to_u64_digits()[0];

        pow_r.0[0].exp_u64(exp) == F::one()
    }

    /// Computes the square root of the septic field extension element.
    /// Returns None if the element is not a square, and Some(result) if it is a square.
    pub fn sqrt(&self) -> Option<Self> {
        let n = *self;

        if n == Self::zero() || n == Self::one() {
            return Some(n);
        }

        if !n.is_square() {
            return None;
        }

        let mut n_iter = n;
        let mut n_power = n;
        for i in 1..30 {
            n_iter *= n_iter;
            if i >= 26 {
                n_power *= n_iter;
            }
        }

        let mut n_frobenius = n_power.frobenius();
        let mut denominator = n_frobenius;
        for i in 2..6 {
            n_frobenius = n_frobenius.frobenius();
            if i % 2 == 1 {
                denominator *= n_frobenius;
            }
        }

        let mut numerator = n;
        numerator *= denominator;
        numerator *= denominator;

        let base = numerator.0[0];
        let g = F::generator();
        let mut a = F::one();
        let mut nonresidue = F::one() - base;
        let legendre_exp = (F::order() - BigUint::one()) / BigUint::from(2u8);

        while nonresidue.exp_u64(legendre_exp.to_u64_digits()[0]) == F::one() {
            a *= g;
            nonresidue = a.square() - base;
        }

        let order = F::order();
        let cipolla_pow = (&order + BigUint::one()) / BigUint::from(2u8);
        let mut x = CipollaExtension::new(a, F::one());
        x = x.pow(&cipolla_pow, nonresidue);

        Some(denominator.inv() * x.real)
    }
}

/// Extension field for Cipolla's algorithm, taken from <https://github.com/Plonky3/Plonky3/pull/439/files>.
#[derive(Clone, Copy, Debug)]
struct CipollaExtension<F: Field> {
    real: F,
    imag: F,
}

impl<F: Field> CipollaExtension<F> {
    fn new(real: F, imag: F) -> Self {
        Self { real, imag }
    }

    fn one() -> Self {
        Self::new(F::one(), F::zero())
    }

    fn mul_ext(&self, other: Self, nonresidue: F) -> Self {
        Self::new(
            self.real * other.real + nonresidue * self.imag * other.imag,
            self.real * other.imag + self.imag * other.real,
        )
    }

    fn pow(&self, exp: &BigUint, nonresidue: F) -> Self {
        let mut result = Self::one();
        let mut base = *self;
        let bits = exp.bits();

        for i in 0..bits {
            if exp.bit(i) {
                result = result.mul_ext(base, nonresidue);
            }
            base = base.mul_ext(base, nonresidue);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;

    use super::*;

    #[test]
    fn test_mul() {
        let a: SepticExtension<BabyBear> = SepticExtension::from_canonical_u32(1);
        let b: SepticExtension<BabyBear> = SepticExtension::from_canonical_u32(2);
        let c = a * b;
        println!("{c}");
    }

    #[test]
    fn test_inv() {
        for i in 0..256 {
            let a: SepticExtension<BabyBear> = SepticExtension([
                BabyBear::from_canonical_u32(i + 3),
                BabyBear::from_canonical_u32(2 * i + 6),
                BabyBear::from_canonical_u32(5 * i + 17),
                BabyBear::from_canonical_u32(6 * i + 91),
                BabyBear::from_canonical_u32(8 * i + 37),
                BabyBear::from_canonical_u32(11 * i + 35),
                BabyBear::from_canonical_u32(14 * i + 33),
            ]);
            let b = a.inv();
            assert_eq!(a * b, SepticExtension::<BabyBear>::one());
        }
    }

    #[test]
    fn test_legendre() {
        let a: SepticExtension<BabyBear> = SepticExtension::generator();
        let mut b = SepticExtension::<BabyBear>::one();
        for i in 1..256 {
            b *= a;
            let c = b.is_square();
            assert!(c == (i % 2 == 0));
        }
    }

    #[test]
    fn test_sqrt() {
        for i in 0..256 {
            let a: SepticExtension<BabyBear> = SepticExtension([
                BabyBear::from_canonical_u32(i + 3),
                BabyBear::from_canonical_u32(2 * i + 6),
                BabyBear::from_canonical_u32(5 * i + 17),
                BabyBear::from_canonical_u32(6 * i + 91),
                BabyBear::from_canonical_u32(8 * i + 37),
                BabyBear::from_canonical_u32(11 * i + 35),
                BabyBear::from_canonical_u32(14 * i + 33),
            ]);
            let b = a * a;
            let recovered_a = b.sqrt().unwrap();
            assert_eq!(recovered_a * recovered_a, b);
        }
        let mut b = SepticExtension::<BabyBear>::one();
        for i in 1..256 {
            let a: SepticExtension<BabyBear> = SepticExtension::generator();
            b *= a;
            let c = b.sqrt();
            if i % 2 == 1 {
                assert!(c.is_none());
            } else {
                let c = c.unwrap();
                assert_eq!(c * c, b);
            }
        }
    }
}
