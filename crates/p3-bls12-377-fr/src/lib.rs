//! The scalar field of the BLS12-377 curve, defined as `Fr` where
//! `r = 8444461749428370424248824938781546531375899335154063827935233455917409239041`.

mod poseidon2;

use core::fmt;
use core::fmt::{Debug, Display, Formatter};
use core::hash::{Hash, Hasher};
use core::iter::{Product, Sum};
use core::ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign};

use ff::{Field as FFField, PrimeField as FFPrimeField, PrimeFieldBits};
use num_bigint::BigUint;
use p3_field::{AbstractField, Field, Packable, PrimeField};
pub use poseidon2::DiffusionMatrixBls12377;
use rand::distributions::{Distribution, Standard};
use rand::Rng;
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(FFPrimeField)]
#[PrimeFieldModulus = "8444461749428370424248824938781546531375899335154063827935233455917409239041"]
#[PrimeFieldGenerator = "22"]
#[PrimeFieldReprEndianness = "little"]
pub struct FFBls12377Fr([u64; 4]);

/// The BLS12-377 curve scalar field prime, defined as
/// `r = 8444461749428370424248824938781546531375899335154063827935233455917409239041`.
#[derive(Copy, Clone, Default, Eq, PartialEq)]
pub struct Bls12377Fr {
    pub value: FFBls12377Fr,
}

impl Bls12377Fr {
    pub(crate) const fn new(value: FFBls12377Fr) -> Self {
        Self { value }
    }
}

impl Serialize for Bls12377Fr {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let repr = self.value.to_repr();
        let bytes = repr.as_ref();

        let mut seq = serializer.serialize_seq(Some(bytes.len()))?;
        for e in bytes {
            seq.serialize_element(&e)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Bls12377Fr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(d)?;

        let mut res = <FFBls12377Fr as FFPrimeField>::Repr::default();
        for (i, digit) in res.0.as_mut().iter_mut().enumerate() {
            *digit = bytes[i];
        }

        let value = FFBls12377Fr::from_repr(res);
        if value.is_some().into() {
            Ok(Self { value: value.unwrap() })
        } else {
            Err(serde::de::Error::custom("Invalid field element"))
        }
    }
}

impl Packable for Bls12377Fr {}

impl Hash for Bls12377Fr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for byte in self.value.to_repr().as_ref().iter() {
            state.write_u8(*byte);
        }
    }
}

impl Ord for Bls12377Fr {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.value.cmp(&other.value)
    }
}

impl PartialOrd for Bls12377Fr {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for Bls12377Fr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        <FFBls12377Fr as Debug>::fmt(&self.value, f)
    }
}

impl Debug for Bls12377Fr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.value, f)
    }
}

impl AbstractField for Bls12377Fr {
    type F = Self;

    fn zero() -> Self {
        Self::new(FFBls12377Fr::ZERO)
    }
    fn one() -> Self {
        Self::new(FFBls12377Fr::ONE)
    }
    fn two() -> Self {
        Self::new(FFBls12377Fr::from(2u64))
    }

    fn neg_one() -> Self {
        Self::new(FFBls12377Fr::ZERO - FFBls12377Fr::ONE)
    }

    #[inline]
    fn from_f(f: Self::F) -> Self {
        f
    }

    fn from_bool(b: bool) -> Self {
        Self::new(FFBls12377Fr::from(b as u64))
    }

    fn from_canonical_u8(n: u8) -> Self {
        Self::new(FFBls12377Fr::from(n as u64))
    }

    fn from_canonical_u16(n: u16) -> Self {
        Self::new(FFBls12377Fr::from(n as u64))
    }

    fn from_canonical_u32(n: u32) -> Self {
        Self::new(FFBls12377Fr::from(n as u64))
    }

    fn from_canonical_u64(n: u64) -> Self {
        Self::new(FFBls12377Fr::from(n))
    }

    fn from_canonical_usize(n: usize) -> Self {
        Self::new(FFBls12377Fr::from(n as u64))
    }

    fn from_wrapped_u32(n: u32) -> Self {
        Self::new(FFBls12377Fr::from(n as u64))
    }

    fn from_wrapped_u64(n: u64) -> Self {
        Self::new(FFBls12377Fr::from(n))
    }

    fn generator() -> Self {
        Self::new(FFBls12377Fr::from(22u64))
    }
}

impl Field for Bls12377Fr {
    type Packing = Self;

    fn is_zero(&self) -> bool {
        self.value.is_zero().into()
    }

    fn try_inverse(&self) -> Option<Self> {
        let inverse = self.value.invert();
        if inverse.is_some().into() {
            Some(Self::new(inverse.unwrap()))
        } else {
            None
        }
    }

    fn order() -> BigUint {
        let bytes = FFBls12377Fr::char_le_bits();
        BigUint::from_bytes_le(bytes.as_raw_slice())
    }
}

impl PrimeField for Bls12377Fr {
    fn as_canonical_biguint(&self) -> BigUint {
        let repr = self.value.to_repr();
        let le_bytes = repr.as_ref();
        BigUint::from_bytes_le(le_bytes)
    }
}

impl Add for Bls12377Fr {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self::new(self.value + rhs.value)
    }
}

impl AddAssign for Bls12377Fr {
    fn add_assign(&mut self, rhs: Self) {
        self.value += rhs.value;
    }
}

impl Sum for Bls12377Fr {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|x, y| x + y).unwrap_or(Self::zero())
    }
}

impl Sub for Bls12377Fr {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self::new(self.value.sub(rhs.value))
    }
}

impl SubAssign for Bls12377Fr {
    fn sub_assign(&mut self, rhs: Self) {
        self.value -= rhs.value;
    }
}

impl Neg for Bls12377Fr {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self * Self::neg_one()
    }
}

impl Mul for Bls12377Fr {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Self::new(self.value * rhs.value)
    }
}

impl MulAssign for Bls12377Fr {
    fn mul_assign(&mut self, rhs: Self) {
        self.value *= rhs.value;
    }
}

impl Product for Bls12377Fr {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|x, y| x * y).unwrap_or(Self::one())
    }
}

impl Div for Bls12377Fr {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self {
        self * rhs.inverse()
    }
}

impl Distribution<Bls12377Fr> for Standard {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Bls12377Fr {
        Bls12377Fr::new(FFBls12377Fr::random(rng))
    }
}

#[cfg(test)]
mod tests {
    use num_traits::One;
    use p3_field_testing::test_field;

    use super::*;

    type F = Bls12377Fr;

    #[test]
    fn test_bls12377fr_sanity() {
        let f = F::new(FFBls12377Fr::from_u128(100));
        assert_eq!(f.as_canonical_biguint(), BigUint::new(vec![100]));

        let f = F::from_canonical_u64(0);
        assert!(f.is_zero());

        let f = F::new(FFBls12377Fr::from_str_vartime(&F::order().to_str_radix(10)).unwrap());
        assert!(f.is_zero());

        assert_eq!(F::generator().as_canonical_biguint(), BigUint::new(vec![22]));

        let f_1 = F::new(FFBls12377Fr::from_u128(1));
        let f_1_copy = F::new(FFBls12377Fr::from_u128(1));

        let expected_result = F::zero();
        assert_eq!(f_1 - f_1_copy, expected_result);

        let expected_result = F::new(FFBls12377Fr::from_u128(2));
        assert_eq!(f_1 + f_1_copy, expected_result);

        let f_2 = F::new(FFBls12377Fr::from_u128(2));
        let expected_result = F::new(FFBls12377Fr::from_u128(3));
        assert_eq!(f_1 + f_1_copy * f_2, expected_result);

        let expected_result = F::new(FFBls12377Fr::from_u128(5));
        assert_eq!(f_1 + f_2 * f_2, expected_result);

        let f_r_minus_1 =
            F::new(FFBls12377Fr::from_str_vartime(&(F::order() - BigUint::one()).to_str_radix(10)).unwrap());
        let expected_result = F::zero();
        assert_eq!(f_1 + f_r_minus_1, expected_result);

        let f_r_minus_2 = F::new(
            FFBls12377Fr::from_str_vartime(&(F::order() - BigUint::new(vec![2])).to_str_radix(10))
                .unwrap(),
        );
        let expected_result = F::new(
            FFBls12377Fr::from_str_vartime(&(F::order() - BigUint::new(vec![3])).to_str_radix(10))
                .unwrap(),
        );
        assert_eq!(f_r_minus_1 + f_r_minus_2, expected_result);

        let expected_result = F::new(FFBls12377Fr::from_u128(1));
        assert_eq!(f_r_minus_1 - f_r_minus_2, expected_result);

        let expected_result = f_r_minus_1;
        assert_eq!(f_r_minus_2 - f_r_minus_1, expected_result);

        let expected_result = f_r_minus_2;
        assert_eq!(f_r_minus_1 - f_1, expected_result);

        let expected_result = F::new(FFBls12377Fr::from_u128(3));
        assert_eq!(f_2 * f_2 - f_1, expected_result);

        let expected_multiplicative_group_generator = F::new(FFBls12377Fr::from_u128(22));
        assert_eq!(F::generator(), expected_multiplicative_group_generator);

        let f_serialized = serde_json::to_string(&f).unwrap();
        let f_deserialized: F = serde_json::from_str(&f_serialized).unwrap();
        assert_eq!(f, f_deserialized);
    }

    test_field!(crate::Bls12377Fr);
}


