use generic_array::GenericArray;
use num::{BigUint, Zero};
use serde::{Deserialize, Serialize};

use crate::utils::ec::field::FieldParameters;
use crate::utils::ec::utils::biguint_to_bits_le;
use crate::utils::ec::{AffinePoint, EllipticCurve, EllipticCurveParameters};

use super::field::NumLimbs;
use super::CurveType;

pub mod bn254;
pub mod secp256k1;

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

impl<E: WeierstrassParameters> EllipticCurve for SwCurve<E> {
    const NB_LIMBS: usize = Self::BaseField::NB_LIMBS;
    const NB_WITNESS_LIMBS: usize = Self::BaseField::NB_WITNESS_LIMBS;

    fn ec_add(p: &AffinePoint<Self>, q: &AffinePoint<Self>) -> AffinePoint<Self> {
        p.sw_add(q)
    }

    fn ec_double(p: &AffinePoint<Self>) -> AffinePoint<Self> {
        p.sw_double()
    }

    fn ec_generator() -> AffinePoint<Self> {
        let (x, y) = E::generator();
        AffinePoint::new(x, y)
    }

    fn ec_neutral() -> Option<AffinePoint<Self>> {
        None
    }

    fn ec_neg(p: &AffinePoint<Self>) -> AffinePoint<Self> {
        let modulus = E::BaseField::modulus();
        AffinePoint::new(p.x.clone(), modulus - &p.y)
    }
}

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

impl<E: WeierstrassParameters> AffinePoint<SwCurve<E>> {
    pub fn sw_add(&self, other: &AffinePoint<SwCurve<E>>) -> AffinePoint<SwCurve<E>> {
        if self.x == other.x && self.y == other.y {
            panic!("Error: Points are the same. Use sw_double instead.");
        }
        let p = E::BaseField::modulus();
        let slope_numerator = (&p + &other.y - &self.y) % &p;
        let slope_denominator = (&p + &other.x - &self.x) % &p;
        let slope_denom_inverse = slope_denominator.modpow(&(&p - 2u32), &p);
        let slope = (slope_numerator * &slope_denom_inverse) % &p;

        let x_3n = (&slope * &slope + &p + &p - &self.x - &other.x) % &p;
        let y_3n = (&slope * &(&p + &self.x - &x_3n) + &p - &self.y) % &p;

        AffinePoint::new(x_3n, y_3n)
    }

    pub fn sw_double(&self) -> AffinePoint<SwCurve<E>> {
        let p = E::BaseField::modulus();
        let a = E::a_int();
        let slope_numerator = (&a + &(&self.x * &self.x) * 3u32) % &p;

        let slope_denominator = (&self.y * 2u32) % &p;
        let slope_denom_inverse = slope_denominator.modpow(&(&p - 2u32), &p);
        let slope = (slope_numerator * &slope_denom_inverse) % &p;

        let x_3n = (&slope * &slope + &p + &p - &self.x - &self.x) % &p;

        let y_3n = (&slope * &(&p + &self.x - &x_3n) + &p - &self.y) % &p;

        AffinePoint::new(x_3n, y_3n)
    }
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
