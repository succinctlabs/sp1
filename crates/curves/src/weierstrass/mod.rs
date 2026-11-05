use elliptic_curve::sec1::FromEncodedPoint;
use generic_array::GenericArray;
use num::{BigUint, Zero};
use secp256k1::Secp256k1Parameters;
use serde::{Deserialize, Serialize};

use super::CurveType;
use crate::{
    params::{FieldParameters, NumLimbs, NumWords},
    utils::biguint_to_bits_le,
    AffinePoint, EllipticCurve, EllipticCurveParameters,
};

#[cfg(feature = "bigint-rug")]
use crate::utils::{biguint_to_rug, rug_to_biguint};

pub mod bls12_381;
pub mod bn254;
pub mod secp256k1;
pub mod secp256r1;

use k256::{AffinePoint as K256AffinePoint, EncodedPoint, FieldElement};

#[cfg(test)]
mod secp256k1_tests;

/// Parameters that specify a short Weierstrass curve : y^2 = x^3 + ax + b.
pub trait WeierstrassParameters: EllipticCurveParameters {
    const A: GenericArray<u8, <Self::BaseField as NumLimbs>::Limbs>;
    const B: GenericArray<u8, <Self::BaseField as NumLimbs>::Limbs>;

    fn generator() -> (BigUint, BigUint);

    fn prime_group_order() -> BigUint;

    fn a_int() -> BigUint {
        let mut modulus = BigUint::zero();
        for (i, limb) in Self::A.iter().enumerate() {
            modulus += BigUint::from(*limb) << (8 * i);
        }
        modulus
    }

    fn b_int() -> BigUint {
        let mut modulus = BigUint::zero();
        for (i, limb) in Self::B.iter().enumerate() {
            modulus += BigUint::from(*limb) << (8 * i);
        }
        modulus
    }

    fn nb_scalar_bits() -> usize {
        Self::BaseField::NB_LIMBS * 16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwCurve<E>(pub E);

impl<E: WeierstrassParameters> WeierstrassParameters for SwCurve<E> {
    const A: GenericArray<u8, <Self::BaseField as NumLimbs>::Limbs> = E::A;
    const B: GenericArray<u8, <Self::BaseField as NumLimbs>::Limbs> = E::B;

    fn a_int() -> BigUint {
        E::a_int()
    }

    fn b_int() -> BigUint {
        E::b_int()
    }

    fn generator() -> (BigUint, BigUint) {
        E::generator()
    }

    fn nb_scalar_bits() -> usize {
        E::nb_scalar_bits()
    }

    fn prime_group_order() -> BigUint {
        E::prime_group_order()
    }
}

impl<E: WeierstrassParameters> EllipticCurveParameters for SwCurve<E> {
    type BaseField = E::BaseField;

    const CURVE_TYPE: CurveType = E::CURVE_TYPE;
}

macro_rules! impl_generic_ec_ops {
    ($curve:ty) => {
        impl EllipticCurve for SwCurve<$curve> {
            const NB_LIMBS: usize = Self::BaseField::NB_LIMBS;
            const NB_WITNESS_LIMBS: usize = Self::BaseField::NB_WITNESS_LIMBS;

            fn ec_add(p: &AffinePoint<Self>, q: &AffinePoint<Self>) -> AffinePoint<Self> {
                p.sw_add(q)
            }

            fn ec_double(p: &AffinePoint<Self>) -> AffinePoint<Self> {
                p.sw_double()
            }

            fn ec_generator() -> AffinePoint<Self> {
                let (x, y) = <$curve as WeierstrassParameters>::generator();
                AffinePoint::new(x, y)
            }

            fn ec_neutral() -> Option<AffinePoint<Self>> {
                None
            }

            fn ec_neg(p: &AffinePoint<Self>) -> AffinePoint<Self> {
                let modulus = <$curve as EllipticCurveParameters>::BaseField::modulus();
                AffinePoint::new(p.x.clone(), modulus - &p.y)
            }
        }
    };
}

impl_generic_ec_ops!(bn254::Bn254Parameters);
impl_generic_ec_ops!(secp256r1::Secp256r1Parameters);
impl_generic_ec_ops!(bls12_381::Bls12381Parameters);

impl<E: WeierstrassParameters> SwCurve<E> {
    pub fn generator() -> AffinePoint<SwCurve<E>> {
        let (x, y) = E::generator();

        AffinePoint::new(x, y)
    }

    pub fn a_int() -> BigUint {
        E::a_int()
    }

    pub fn b_int() -> BigUint {
        E::b_int()
    }
}

impl<E: WeierstrassParameters> AffinePoint<SwCurve<E>> {
    pub fn sw_scalar_mul(&self, scalar: &BigUint) -> Self {
        let mut result: Option<AffinePoint<SwCurve<E>>> = None;
        let mut temp = self.clone();
        let bits = biguint_to_bits_le(scalar, E::nb_scalar_bits());
        for bit in bits {
            if bit {
                result = result.map(|r| r.sw_add(&temp)).or(Some(temp.clone()));
            }
            temp = temp.sw_double();
        }
        result.unwrap()
    }
}

pub fn biguint_to_dashu(integer: &BigUint) -> dashu::integer::UBig {
    dashu::integer::UBig::from_le_bytes(integer.to_bytes_le().as_slice())
}

pub fn dashu_to_biguint(integer: &dashu::integer::UBig) -> BigUint {
    BigUint::from_bytes_le(&integer.to_le_bytes())
}

pub fn dashu_modpow(
    base: &dashu::integer::UBig,
    exponent: &dashu::integer::UBig,
    modulus: &dashu::integer::UBig,
) -> dashu::integer::UBig {
    if modulus == &dashu::integer::UBig::from(1u32) {
        return dashu::integer::UBig::from(0u32);
    }

    let mut result = dashu::integer::UBig::from(1u32);
    let mut base = base.clone() % modulus;
    let mut exp = exponent.clone();

    while exp > dashu::integer::UBig::from(0u32) {
        if &exp % dashu::integer::UBig::from(2u32) == dashu::integer::UBig::from(1u32) {
            result = (result * &base) % modulus;
        }
        exp >>= 1;
        base = (&base * &base) % modulus;
    }

    result
}

impl EllipticCurve for SwCurve<Secp256k1Parameters> {
    fn ec_add(p: &AffinePoint<Self>, q: &AffinePoint<Self>) -> AffinePoint<Self> {
        p.sw_add_k256(q)
    }

    fn ec_double(p: &AffinePoint<Self>) -> AffinePoint<Self> {
        p.sw_double_k256()
    }

    fn ec_generator() -> AffinePoint<Self> {
        let (x, y) = Secp256k1Parameters::generator();
        AffinePoint::new(x, y)
    }

    fn ec_neutral() -> Option<AffinePoint<Self>> {
        None
    }

    fn ec_neg(p: &AffinePoint<Self>) -> AffinePoint<Self> {
        let modulus = <Secp256k1Parameters as EllipticCurveParameters>::BaseField::modulus();
        AffinePoint::new(p.x.clone(), modulus - &p.y)
    }
}

impl AffinePoint<SwCurve<Secp256k1Parameters>> {
    fn k256_coordinates(&self) -> (FieldElement, FieldElement) {
        let encoded = EncodedPoint::from_bytes(self.to_sec1_uncompressed()).unwrap();
        // Preserve SEC1's canonical-coordinate and curve-membership checks.
        K256AffinePoint::from_encoded_point(&encoded).unwrap();
        (
            FieldElement::from_bytes(encoded.x().unwrap()).unwrap(),
            FieldElement::from_bytes(encoded.y().unwrap()).unwrap(),
        )
    }

    pub fn sw_add_k256(&self, other: &Self) -> Self {
        // The curve helper historically supports equal points.
        if self == other {
            return self.sw_double_k256();
        }
        let (x1, y1) = self.k256_coordinates();
        let (x2, y2) = other.k256_coordinates();
        let slope = (y2 - y1) * secp256k1_inverse(x2 - x1);
        Self::k256_from_slope(x1, y1, x2, slope)
    }

    pub fn sw_double_k256(&self) -> Self {
        let (x, y) = self.k256_coordinates();
        let slope = x.square().mul_single(3) * secp256k1_inverse(y.double());
        Self::k256_from_slope(x, y, x, slope)
    }

    fn k256_from_slope(
        x1: FieldElement,
        y1: FieldElement,
        x2: FieldElement,
        slope: FieldElement,
    ) -> Self {
        // Subtraction uses negates assuming magnitude 1, so normalize x3 beforehand.
        // All multiplication/squaring inputs here have magnitude <= 8, as required by k256.
        let x3 = (slope.square() - x1 - x2).normalize_weak();
        let y3 = slope * (x1 - x3) - y1;
        AffinePoint::new(
            BigUint::from_bytes_be(&x3.to_bytes()),
            BigUint::from_bytes_be(&y3.to_bytes()),
        )
    }
}

/// Variable-time inversion for host execution, which already uses variable-time bigint arithmetic.
/// Keep the other field operations in k256 to avoid bigint allocation and reduction for each one.
fn secp256k1_inverse(value: FieldElement) -> FieldElement {
    use dashu::integer::{fast_div::ConstDivisor, UBig};
    use std::sync::LazyLock;

    static MODULUS: LazyLock<ConstDivisor> = LazyLock::new(|| {
        ConstDivisor::new(biguint_to_dashu(
            &<Secp256k1Parameters as EllipticCurveParameters>::BaseField::modulus(),
        ))
    });
    let inverse = MODULUS
        .reduce(UBig::from_be_bytes(&value.to_bytes()))
        .inv()
        .expect("secp256k1 result is the point at infinity")
        .residue()
        .to_be_bytes();
    let mut bytes = k256::FieldBytes::default();
    bytes[32 - inverse.len()..].copy_from_slice(&inverse);
    FieldElement::from_bytes(&bytes).unwrap()
}

impl<E: WeierstrassParameters> AffinePoint<SwCurve<E>> {
    pub fn sw_add(&self, other: &AffinePoint<SwCurve<E>>) -> AffinePoint<SwCurve<E>> {
        if self.x == other.x && self.y == other.y {
            panic!("Error: Points are the same. Use sw_double instead.");
        }

        cfg_if::cfg_if! {
            if #[cfg(feature = "bigint-rug")] {
                self.sw_add_rug(other)
            } else {
                let p = biguint_to_dashu(&E::BaseField::modulus());
                let self_x = biguint_to_dashu(&self.x);
                let self_y = biguint_to_dashu(&self.y);
                let other_x = biguint_to_dashu(&other.x);
                let other_y = biguint_to_dashu(&other.y);

                let slope_numerator = (&p + &other_y - &self_y) % &p;
                let slope_denominator = (&p + &other_x - &self_x) % &p;
                let slope_denom_inverse =
                    dashu_modpow(&slope_denominator, &(&p - &dashu::integer::UBig::from(2u32)), &p);
                let slope = (slope_numerator * &slope_denom_inverse) % &p;

                let x_3n = (&slope * &slope + &p + &p - &self_x - &other_x) % &p;
                let y_3n = (&slope * &(&p + &self_x - &x_3n) + &p - &self_y) % &p;

                AffinePoint::new(dashu_to_biguint(&x_3n), dashu_to_biguint(&y_3n))
            }
        }
    }

    pub fn sw_double(&self) -> AffinePoint<SwCurve<E>> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "bigint-rug")] {
                self.sw_double_rug()
            } else {
                let p = biguint_to_dashu(&E::BaseField::modulus());
                let a = biguint_to_dashu(&E::a_int());

                let self_x = biguint_to_dashu(&self.x);
                let self_y = biguint_to_dashu(&self.y);

                let slope_numerator = (&a + &(&self_x * &self_x) * 3u32) % &p;

                let slope_denominator = (&self_y * 2u32) % &p;
                let slope_denom_inverse =
                    dashu_modpow(&slope_denominator, &(&p - &dashu::integer::UBig::from(2u32)), &p);
                // let slope_denom_inverse = slope_denominator.modpow(&(&p - 2u32), &p);
                let slope = (slope_numerator * &slope_denom_inverse) % &p;

                let x_3n = (&slope * &slope + &p + &p - &self_x - &self_x) % &p;

                let y_3n = (&slope * &(&p + &self_x - &x_3n) + &p - &self_y) % &p;

                AffinePoint::new(dashu_to_biguint(&x_3n), dashu_to_biguint(&y_3n))
            }
        }
    }

    #[cfg(feature = "bigint-rug")]
    pub fn sw_add_rug(&self, other: &AffinePoint<SwCurve<E>>) -> AffinePoint<SwCurve<E>> {
        use rug::Complete;
        let p = biguint_to_rug(&E::BaseField::modulus());
        let self_x = biguint_to_rug(&self.x);
        let self_y = biguint_to_rug(&self.y);
        let other_x = biguint_to_rug(&other.x);
        let other_y = biguint_to_rug(&other.y);

        let slope_numerator = ((&p + &other_y).complete() - &self_y) % &p;
        let slope_denominator = ((&p + &other_x).complete() - &self_x) % &p;
        let slope_denom_inverse = slope_denominator
            .pow_mod_ref(&(&p - &rug::Integer::from(2u32)).complete(), &p)
            .unwrap()
            .complete();
        let slope = (slope_numerator * &slope_denom_inverse) % &p;

        let x_3n = ((&slope * &slope + &p).complete() + &p - &self_x - &other_x) % &p;
        let y_3n = ((&slope * &((&p + &self_x).complete() - &x_3n) + &p).complete() - &self_y) % &p;

        AffinePoint::new(rug_to_biguint(&x_3n), rug_to_biguint(&y_3n))
    }

    #[cfg(feature = "bigint-rug")]
    pub fn sw_double_rug(&self) -> AffinePoint<SwCurve<E>> {
        use rug::Complete;
        let p = biguint_to_rug(&E::BaseField::modulus());
        let a = biguint_to_rug(&E::a_int());

        let self_x = biguint_to_rug(&self.x);
        let self_y = biguint_to_rug(&self.y);

        let slope_numerator = (&a + &(&self_x * &self_x).complete() * 3u32).complete() % &p;

        let slope_denominator = (&self_y * 2u32).complete() % &p;
        let slope_denom_inverse = slope_denominator
            .pow_mod_ref(&(&p - &rug::Integer::from(2u32)).complete(), &p)
            .unwrap()
            .complete();

        let slope = (slope_numerator * &slope_denom_inverse) % &p;

        let x_3n = ((&slope * &slope + &p).complete() + ((&p - &self_x).complete() - &self_x)) % &p;

        let y_3n = ((&slope * &((&p + &self_x).complete() - &x_3n) + &p).complete() - &self_y) % &p;

        AffinePoint::new(rug_to_biguint(&x_3n), rug_to_biguint(&y_3n))
    }
}

#[derive(Debug)]
pub enum FieldType {
    Bls12381,
    Bn254,
}

pub trait FpOpField: FieldParameters + NumWords {
    const FIELD_TYPE: FieldType;
}

#[cfg(test)]
mod tests {

    use num::bigint::RandBigInt;
    use rand::thread_rng;

    use super::bn254;

    #[test]
    fn test_weierstrass_biguint_scalar_mul() {
        type E = bn254::Bn254;
        let base = E::generator();

        let mut rng = thread_rng();
        for _ in 0..10 {
            let x = rng.gen_biguint(24);
            let y = rng.gen_biguint(25);

            let x_base = base.sw_scalar_mul(&x);
            let y_x_base = x_base.sw_scalar_mul(&y);
            let xy = &x * &y;
            let xy_base = base.sw_scalar_mul(&xy);
            assert_eq!(y_x_base, xy_base);
        }
    }
}
