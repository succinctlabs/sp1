use elliptic_curve::sec1::FromEncodedPoint;
use generic_array::GenericArray;
use num::{BigUint, Zero};
use secp256k1::Secp256k1Parameters;
use serde::{Deserialize, Serialize};

use super::CurveType;
use crate::{
    params::{FieldParameters, NumLimbs, NumWords},
    utils::{biguint_to_bits_le, biguint_to_u256},
    AffinePoint, EllipticCurve, EllipticCurveParameters,
};

#[cfg(not(feature = "bigint-rug"))]
use crate::utils::{biguint_to_dashu, dashu_modpow, dashu_to_biguint};

#[cfg(feature = "bigint-rug")]
use crate::utils::{biguint_to_rug, rug_to_biguint};

pub mod bls12_381;
pub mod bn254;
pub mod secp256k1;
pub mod secp256r1;

use k256::{
    elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint},
    AffinePoint as K256AffinePoint, EncodedPoint, ProjectivePoint as K256ProjectivePoint,
};

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

impl EllipticCurve for SwCurve<Secp256k1Parameters> {
    fn ec_add(p: &AffinePoint<Self>, q: &AffinePoint<Self>) -> AffinePoint<Self> {
        p.sw_add_k256(q)
    }

    fn ec_double(p: &AffinePoint<Self>) -> AffinePoint<Self> {
        p.sw_double_k256()
    }

    /// Scalar multiplication via the `k256` crate's projective-coordinate path.
    ///
    /// # Panics
    ///
    /// Panics with `"Scalar multiplication failed"` when `scalar` reduces to zero mod the
    /// secp256k1 group order `n` (the result would be the point at infinity, which has no
    /// affine representation). This includes `scalar = 0` and any nonzero multiple of `n`.
    ///
    /// # Warning
    ///
    /// `scalar` is funneled through [`crate::utils::biguint_to_u256`], which silently truncates
    /// inputs that don't fit in 256 bits (the `debug_assert!` in
    /// [`crate::utils::biguint_to_limbs`] only fires in debug builds). Callers must ensure
    /// `scalar < 2^256`, or the multiplication will silently use a different scalar than
    /// intended. This differs from the generic [`EllipticCurve::ec_mul`] default impl, which
    /// reduces mod `2^Self::nb_scalar_bits()` instead.
    fn ec_mul(p: &AffinePoint<Self>, scalar: &BigUint) -> AffinePoint<Self> {
        p.sw_scalar_mul_k256(scalar)
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
    pub fn sw_add_k256(&self, other: &Self) -> Self {
        let this_bytes = self.to_sec1_uncompressed();
        let other_bytes = other.to_sec1_uncompressed();

        let this: K256AffinePoint =
            K256AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(this_bytes).unwrap())
                .unwrap();
        let this = K256ProjectivePoint::from(this);

        let other =
            K256AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(other_bytes).unwrap())
                .unwrap();
        let other = K256ProjectivePoint::from(other);

        let result = this + other;
        let result = result.to_affine();
        // Save it as a uncompressed point
        let result_bytes = result.to_encoded_point(false);
        let result_bytes = result_bytes.as_bytes();

        // Skip the first byte which is the compression flag
        AffinePoint::new(
            BigUint::from_bytes_be(&result_bytes[1..33]),
            BigUint::from_bytes_be(&result_bytes[33..65]),
        )
    }

    pub fn sw_double_k256(&self) -> Self {
        let this_bytes = self.to_sec1_uncompressed();
        let this =
            K256AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(this_bytes).unwrap())
                .unwrap();

        let this = K256ProjectivePoint::from(this);

        let result = this.double();
        let result = result.to_affine();

        // Save it as a uncompressed point
        let result_bytes = result.to_encoded_point(false);
        let result_bytes = result_bytes.as_bytes();

        // Skip the first byte which is the compression flag
        AffinePoint::new(
            BigUint::from_bytes_be(&result_bytes[1..33]),
            BigUint::from_bytes_be(&result_bytes[33..65]),
        )
    }

    /// Multiplies `self` by `scalar` using the `k256` crate's projective-coordinate scalar
    /// multiplication. This is the body of the [`EllipticCurve::ec_mul`] override for
    /// `SwCurve<Secp256k1Parameters>`; see that impl for panic conditions and the 256-bit
    /// truncation caveat.
    pub fn sw_scalar_mul_k256(&self, scalar: &BigUint) -> Self {
        let this_bytes = self.to_sec1_uncompressed();
        let this =
            K256AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(this_bytes).unwrap())
                .unwrap();
        let this = K256ProjectivePoint::from(this);

        let scalar = k256::Scalar::reduce(biguint_to_u256(scalar));

        // `0 · P = ∞` has no affine representation. Match the contract of the generic `ec_mul`
        // default impl and panic. This also catches non-zero scalars that are multiples of the
        // group order `n`, since `Scalar::reduce` brings them to zero.
        if bool::from(scalar.is_zero()) {
            panic!("Scalar multiplication failed");
        }

        let result = this * scalar;
        let result = result.to_affine();

        // Save it as a uncompressed point
        let result_bytes = result.to_encoded_point(false);
        let result_bytes = result_bytes.as_bytes();

        // Skip the first byte which is the compression flag
        AffinePoint::new(
            BigUint::from_bytes_be(&result_bytes[1..33]),
            BigUint::from_bytes_be(&result_bytes[33..65]),
        )
    }
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

    use super::{bn254, secp256k1};

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

    /// Cross-check the `k256`-backed scalar multiplication against the generic double-and-add
    /// `sw_scalar_mul`. Both should produce the same `AffinePoint` for any scalar (including
    /// scalars >= n, since `k * P = (k mod n) * P` on a prime-order curve).
    #[test]
    fn test_secp256k1_sw_scalar_mul_k256_matches_generic() {
        type E = secp256k1::Secp256k1;
        let base = E::generator();

        let mut rng = thread_rng();
        for _ in 0..10 {
            let scalar = rng.gen_biguint(256);
            let generic = base.sw_scalar_mul(&scalar);
            let optimized = base.sw_scalar_mul_k256(&scalar);
            assert_eq!(generic, optimized, "mismatch for scalar = {scalar}");
        }
    }
}
