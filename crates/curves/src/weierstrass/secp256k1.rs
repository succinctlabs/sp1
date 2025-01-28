//! Modulo defining the Secp256k1 curve and its base field. The constants are all taken from
//! https://en.bitcoin.it/wiki/Secp256k1.

use std::str::FromStr;

use elliptic_curve::{sec1::ToEncodedPoint, subtle::Choice};
use generic_array::GenericArray;
use k256::{elliptic_curve::point::DecompressPoint, FieldElement};
use num::{
    traits::{FromBytes, ToBytes},
    BigUint, Zero,
};
use serde::{Deserialize, Serialize};
use typenum::{U32, U62};

use super::{SwCurve, WeierstrassParameters};
use crate::{
    params::{FieldParameters, NumLimbs},
    AffinePoint, CurveType, EllipticCurve, EllipticCurveParameters,
};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Secp256k1 curve parameter
pub struct Secp256k1Parameters;

pub type Secp256k1 = SwCurve<Secp256k1Parameters>;

#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Secp256k1 base field parameter
pub struct Secp256k1BaseField;

impl FieldParameters for Secp256k1BaseField {
    const MODULUS: &'static [u8] = &[
        0x2f, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ];

    /// A rough witness-offset estimate given the size of the limbs and the size of the field.
    const WITNESS_OFFSET: usize = 1usize << 14;

    fn modulus() -> BigUint {
        BigUint::from_bytes_le(Self::MODULUS)
    }
}

impl NumLimbs for Secp256k1BaseField {
    type Limbs = U32;
    type Witness = U62;
}

impl EllipticCurveParameters for Secp256k1Parameters {
    type BaseField = Secp256k1BaseField;
    const CURVE_TYPE: CurveType = CurveType::Secp256k1;
}

impl WeierstrassParameters for Secp256k1Parameters {
    const A: GenericArray<u8, U32> = GenericArray::from_array([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);

    const B: GenericArray<u8, U32> = GenericArray::from_array([
        7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    fn generator() -> (BigUint, BigUint) {
        let x = BigUint::from_str(
            "55066263022277343669578718895168534326250603453777594175500187360389116729240",
        )
        .unwrap();
        let y = BigUint::from_str(
            "32670510020758816978083085130507043184471273380659243275938904335757337482424",
        )
        .unwrap();
        (x, y)
    }

    fn prime_group_order() -> num::BigUint {
        BigUint::from_slice(&[
            0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF,
        ])
    }

    fn a_int() -> BigUint {
        BigUint::zero()
    }

    fn b_int() -> BigUint {
        BigUint::from(7u32)
    }
}

pub fn secp256k1_decompress<E: EllipticCurve>(bytes_be: &[u8], sign: u32) -> AffinePoint<E> {
    let computed_point =
        k256::AffinePoint::decompress(bytes_be.into(), Choice::from(sign as u8)).unwrap();
    let point = computed_point.to_encoded_point(false);

    let x = BigUint::from_bytes_be(point.x().unwrap());
    let y = BigUint::from_bytes_be(point.y().unwrap());
    AffinePoint::<E>::new(x, y)
}

pub fn secp256k1_sqrt(n: &BigUint) -> BigUint {
    let be_bytes = n.to_be_bytes();
    let mut bytes = [0_u8; 32];
    bytes[32 - be_bytes.len()..].copy_from_slice(&be_bytes);
    let fe = FieldElement::from_bytes(&bytes.into()).unwrap();
    let result_bytes = fe.sqrt().unwrap().normalize().to_bytes();
    BigUint::from_be_bytes(&result_bytes as &[u8])
}

#[cfg(test)]
mod tests {
    #![allow(clippy::print_stdout)]

    use super::*;
    use crate::utils::biguint_from_limbs;
    use num::bigint::RandBigInt;
    use rand::thread_rng;

    #[test]
    fn test_weierstrass_biguint_scalar_mul() {
        assert_eq!(biguint_from_limbs(Secp256k1BaseField::MODULUS), Secp256k1BaseField::modulus());
    }

    #[test]
    fn test_secp256k_sqrt() {
        let mut rng = thread_rng();
        for _ in 0..10 {
            // Check that sqrt(x^2)^2 == x^2
            // We use x^2 since not all field elements have a square root
            let x = rng.gen_biguint(256) % Secp256k1BaseField::modulus();
            let x_2 = (&x * &x) % Secp256k1BaseField::modulus();
            let sqrt = secp256k1_sqrt(&x_2);

            println!("sqrt: {}", sqrt);

            let sqrt_2 = (&sqrt * &sqrt) % Secp256k1BaseField::modulus();

            assert_eq!(sqrt_2, x_2);
        }
    }
}
