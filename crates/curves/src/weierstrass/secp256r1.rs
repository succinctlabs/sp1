//! Modulo defining the Secp256r1 curve and its base field. The constants are all taken from
//! https://neuromancer.sk/std/secg/secp256r1

use std::str::FromStr;

use elliptic_curve::{sec1::ToEncodedPoint, subtle::Choice};
use generic_array::GenericArray;
use num::{
    traits::{FromBytes, ToBytes},
    BigUint,
};
use p256::{elliptic_curve::point::DecompressPoint, FieldElement};
use serde::{Deserialize, Serialize};
use typenum::{U32, U62};

use super::{SwCurve, WeierstrassParameters};
use crate::{
    params::{FieldParameters, NumLimbs},
    AffinePoint, CurveType, EllipticCurve, EllipticCurveParameters,
};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Secp256r1 curve parameter
pub struct Secp256r1Parameters;

pub type Secp256r1 = SwCurve<Secp256r1Parameters>;

#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Secp256r1 base field parameter
pub struct Secp256r1BaseField;

impl FieldParameters for Secp256r1BaseField {
    const MODULUS: &'static [u8] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff,
        0xff, 0xff,
    ];
    /// A rough witness-offset estimate given the size of the limbs and the size of the field.
    const WITNESS_OFFSET: usize = 1usize << 14;

    fn modulus() -> BigUint {
        BigUint::from_bytes_le(Self::MODULUS)
    }
}

impl NumLimbs for Secp256r1BaseField {
    type Limbs = U32;
    type Witness = U62;
}

impl EllipticCurveParameters for Secp256r1Parameters {
    type BaseField = Secp256r1BaseField;
    const CURVE_TYPE: CurveType = CurveType::Secp256r1;
}

impl WeierstrassParameters for Secp256r1Parameters {
    const A: GenericArray<u8, U32> = GenericArray::from_array([
        252, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 1, 0, 0, 0, 255, 255, 255, 255,
    ]);

    const B: GenericArray<u8, U32> = GenericArray::from_array([
        75, 96, 210, 39, 62, 60, 206, 59, 246, 176, 83, 204, 176, 6, 29, 101, 188, 134, 152, 118,
        85, 189, 235, 179, 231, 147, 58, 170, 216, 53, 198, 90,
    ]);

    fn generator() -> (BigUint, BigUint) {
        let x = BigUint::from_str(
            "48439561293906451759052585252797914202762949526041747995844080717082404635286",
        )
        .unwrap();
        let y = BigUint::from_str(
            "36134250956749795798585127919587881956611106672985015071877198253568414405109",
        )
        .unwrap();
        (x, y)
    }

    fn prime_group_order() -> num::BigUint {
        BigUint::from_slice(&[
            0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
            0xFFFFFFFF,
        ])
    }

    fn a_int() -> BigUint {
        BigUint::from_slice(&[
            0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001,
            0xFFFFFFFF,
        ])
    }

    fn b_int() -> BigUint {
        BigUint::from_slice(&[
            0x27D2604B, 0x3BCE3C3E, 0xCC53B0F6, 0x651D06B0, 0x769886BC, 0xB3EBBD55, 0xAA3A93E7,
            0x5AC635D8,
        ])
    }
}

pub fn secp256r1_decompress<E: EllipticCurve>(bytes_be: &[u8], sign: u32) -> AffinePoint<E> {
    let computed_point =
        p256::AffinePoint::decompress(bytes_be.into(), Choice::from(sign as u8)).unwrap();
    let point = computed_point.to_encoded_point(false);

    let x = BigUint::from_bytes_be(point.x().unwrap());
    let y = BigUint::from_bytes_be(point.y().unwrap());
    AffinePoint::<E>::new(x, y)
}

pub fn secp256r1_sqrt(n: &BigUint) -> BigUint {
    let be_bytes = n.to_be_bytes();
    let mut bytes = [0_u8; 32];
    bytes[32 - be_bytes.len()..].copy_from_slice(&be_bytes);
    let fe = FieldElement::from_bytes(&bytes.into()).unwrap();
    let result_bytes = fe.sqrt().unwrap().to_bytes();
    BigUint::from_be_bytes(&result_bytes as &[u8])
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::utils::biguint_from_limbs;
    use num::bigint::RandBigInt;
    use rand::thread_rng;

    #[test]
    fn test_weierstrass_biguint_scalar_mul() {
        assert_eq!(biguint_from_limbs(Secp256r1BaseField::MODULUS), Secp256r1BaseField::modulus());
    }

    #[test]
    fn test_secp256r_sqrt() {
        let mut rng = thread_rng();
        for _ in 0..10 {
            // Check that sqrt(x^2)^2 == x^2
            // We use x^2 since not all field elements have a square root
            let x = rng.gen_biguint(256) % Secp256r1BaseField::modulus();
            let x_2 = (&x * &x) % Secp256r1BaseField::modulus(); // x^2
            let sqrt = secp256r1_sqrt(&x_2); //sqrt(x^2) = x
            let sqrt_2 = (&sqrt * &sqrt) % Secp256r1BaseField::modulus();

            assert_eq!(sqrt_2, x_2);
        }
    }
}
