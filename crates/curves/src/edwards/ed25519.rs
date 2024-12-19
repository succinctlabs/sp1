use std::str::FromStr;

use crate::curve25519_dalek::CompressedEdwardsY;
use generic_array::GenericArray;
use num::{BigUint, Num, One};
use serde::{Deserialize, Serialize};
use typenum::{U32, U62};

use crate::{
    edwards::{EdwardsCurve, EdwardsParameters},
    params::{FieldParameters, NumLimbs},
    AffinePoint, CurveType, EllipticCurveParameters,
};

pub type Ed25519 = EdwardsCurve<Ed25519Parameters>;

#[derive(Default, Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Ed25519Parameters;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Ed25519BaseField;

impl FieldParameters for Ed25519BaseField {
    const MODULUS: &'static [u8] = &[
        237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
    ];

    const WITNESS_OFFSET: usize = 1usize << 14;

    fn modulus() -> BigUint {
        (BigUint::one() << 255) - BigUint::from(19u32)
    }
}

impl NumLimbs for Ed25519BaseField {
    type Limbs = U32;
    type Witness = U62;
}

impl EllipticCurveParameters for Ed25519Parameters {
    type BaseField = Ed25519BaseField;
    const CURVE_TYPE: CurveType = CurveType::Ed25519;
}

impl EdwardsParameters for Ed25519Parameters {
    const D: GenericArray<u8, U32> = GenericArray::from_array([
        163, 120, 89, 19, 202, 77, 235, 117, 171, 216, 65, 65, 77, 10, 112, 0, 152, 232, 121, 119,
        121, 64, 199, 140, 115, 254, 111, 43, 238, 108, 3, 82,
    ]);

    fn prime_group_order() -> BigUint {
        BigUint::from(2u32).pow(252) + BigUint::from(27742317777372353535851937790883648493u128)
    }

    fn generator() -> (BigUint, BigUint) {
        let x = BigUint::from_str_radix(
            "15112221349535400772501151409588531511454012693041857206046113283949847762202",
            10,
        )
        .unwrap();
        let y = BigUint::from_str_radix(
            "46316835694926478169428394003475163141307993866256225615783033603165251855960",
            10,
        )
        .unwrap();
        (x, y)
    }
}

/// Computes the square root of a number in the base field of Ed25519.
///
/// This function always returns the nonnegative square root, in the sense that the least
/// significant bit of the result is always 0.
pub fn ed25519_sqrt(a: &BigUint) -> Option<BigUint> {
    // Here is a description of how to calculate sqrt in the Curve25519 base field:
    // ssh://git@github.com/succinctlabs/curve25519-dalek/blob/
    // e2d1bd10d6d772af07cac5c8161cd7655016af6d/curve25519-dalek/src/field.rs#L256

    let modulus = Ed25519BaseField::modulus();
    // The exponent is (modulus+3)/8;
    let mut beta = a.modpow(
        &BigUint::from_str(
            "7237005577332262213973186563042994240829374041602535252466099000494570602494",
        )
        .unwrap(),
        &modulus,
    );

    // The square root of -1 in the field.
    // Take from here:
    // ssh://git@github.com/succinctlabs/curve25519-dalek/blob/
    // e2d1bd10d6d772af07cac5c8161cd7655016af6d/curve25519-dalek/src/backend/serial/u64/constants.
    // rs#L89
    let sqrt_m1 = BigUint::from_str(
        "19681161376707505956807079304988542015446066515923890162744021073123829784752",
    )
    .unwrap();

    let beta_squared = &beta * &beta % &modulus;
    let neg_a = &modulus - a;

    if beta_squared == neg_a {
        beta = (&beta * &sqrt_m1) % &modulus;
    }

    let correct_sign_sqrt = &beta_squared == a;
    let flipped_sign_sqrt = beta_squared == neg_a;

    if !correct_sign_sqrt && !flipped_sign_sqrt {
        return None;
    }

    let beta_bytes = beta.to_bytes_le();
    if (beta_bytes[0] & 1) == 1 {
        beta = (&modulus - &beta) % &modulus;
    }

    Some(beta)
}

pub fn decompress(compressed_point: &CompressedEdwardsY) -> Option<AffinePoint<Ed25519>> {
    let mut point_bytes = *compressed_point.as_bytes();
    let sign = point_bytes[31] >> 7 == 1;
    // mask out the sign bit
    point_bytes[31] &= 0b0111_1111;
    let modulus = &Ed25519BaseField::modulus();

    let y = &BigUint::from_bytes_le(&point_bytes);
    let yy = &((y * y) % modulus);
    let u = (yy - BigUint::one()) % modulus; // u =  y²-1
    let v = &((yy * &Ed25519Parameters::d_biguint()) + &BigUint::one()) % modulus; // v = dy²+1

    let v_inv = v.modpow(&(modulus - BigUint::from(2u64)), modulus);
    let u_div_v = (u * &v_inv) % modulus;

    let mut x = ed25519_sqrt(&u_div_v)?;

    // sqrt always returns the nonnegative square root,
    // so we negate according to the supplied sign bit.
    if sign {
        x = modulus - &x;
    }

    Some(AffinePoint::new(x, y.clone()))
}

#[cfg(test)]
mod tests {

    use super::*;
    use num::traits::ToBytes;

    const NUM_TEST_CASES: usize = 100;

    #[test]
    fn test_ed25519_decompress() {
        // This test checks that decompression of generator, 2x generator, 4x generator, etc. works.

        // Get the generator point.
        let mut point = {
            let (x, y) = Ed25519Parameters::generator();
            AffinePoint::<EdwardsCurve<Ed25519Parameters>>::new(x, y)
        };
        for _ in 0..NUM_TEST_CASES {
            // Compress the point. The first 255 bits of a compressed point is the y-coordinate. The
            // high bit of the 32nd byte gives the "sign" of x, which is the parity.
            let compressed_point = {
                let x = point.x.to_le_bytes();
                let y = point.y.to_le_bytes();
                let mut compressed = [0u8; 32];

                // Copy y into compressed.
                compressed[..y.len()].copy_from_slice(&y);

                // Set the sign bit.
                compressed[31] |= (x[0] & 1) << 7;

                CompressedEdwardsY(compressed)
            };
            assert_eq!(point, decompress(&compressed_point).unwrap());

            // Double the point to create a "random" point for the next iteration.
            point = point.clone() + point.clone();
        }
    }
}
