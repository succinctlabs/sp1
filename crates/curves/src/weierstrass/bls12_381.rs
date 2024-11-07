use amcl::bls381::{big::Big, bls381::utils::deserialize_g1, fp::FP};
use generic_array::GenericArray;
use num::{BigUint, Num, Zero};
use serde::{Deserialize, Serialize};
use typenum::{U48, U94};

use super::{FieldType, FpOpField, SwCurve, WeierstrassParameters};
use crate::{
    params::{FieldParameters, NumLimbs},
    CurveType, EllipticCurveParameters,
};

/// Bls12-381 curve parameter
use crate::{AffinePoint, EllipticCurve};

// Serialization flags
const COMPRESSION_FLAG: u8 = 0b_1000_0000;
const Y_IS_ODD_FLAG: u8 = 0b_0010_0000;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Bls12381 curve parameter
pub struct Bls12381Parameters;

pub type Bls12381 = SwCurve<Bls12381Parameters>;

#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Bls12381 base field parameter
pub struct Bls12381BaseField;

impl FieldParameters for Bls12381BaseField {
    // The modulus has been taken from py_ecc python library by Ethereum Foundation.
    // // https://github.com/ethereum/py_ecc/blob/7b9e1b3/py_ecc/fields/field_properties.py#L30
    // The below value is the little-endian representation of the modulus.
    const NB_LIMBS: usize = 48;

    const MODULUS: &'static [u8] = &[
        171, 170, 255, 255, 255, 255, 254, 185, 255, 255, 83, 177, 254, 255, 171, 30, 36, 246, 176,
        246, 160, 210, 48, 103, 191, 18, 133, 243, 132, 75, 119, 100, 215, 172, 75, 67, 182, 167,
        27, 75, 154, 230, 127, 57, 234, 17, 1, 26,
    ];

    // A rough witness-offset estimate given the size of the limbs and the size of the field.
    const WITNESS_OFFSET: usize = 1usize << 15;

    fn modulus() -> BigUint {
        BigUint::from_str_radix(
            "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787",
            10,
        )
        .unwrap()
    }
}

impl FpOpField for Bls12381BaseField {
    const FIELD_TYPE: FieldType = FieldType::Bls12381;
}

impl NumLimbs for Bls12381BaseField {
    type Limbs = U48;
    type Witness = U94;
}

impl EllipticCurveParameters for Bls12381Parameters {
    type BaseField = Bls12381BaseField;
    const CURVE_TYPE: CurveType = CurveType::Bls12381;
}

impl WeierstrassParameters for Bls12381Parameters {
    // The values of `A` and `B` has been taken from py_ecc python library by Ethereum Foundation.
    // https://github.com/ethereum/py_ecc/blob/7b9e1b3/py_ecc/bls12_381/bls12_381_curve.py#L31
    const A: GenericArray<u8, U48> = GenericArray::from_array([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);

    const B: GenericArray<u8, U48> = GenericArray::from_array([
        4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);

    fn generator() -> (BigUint, BigUint) {
        let x = BigUint::from_str_radix(
            "3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507",
            10,
        )
        .unwrap();
        let y = BigUint::from_str_radix(
            "1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569",
            10,
        )
        .unwrap();
        (x, y)
    }

    // The prime group order has been taken from py_ecc python library by Ethereum Foundation.
    // https://github.com/ethereum/py_ecc/blob/7b9e1b3/py_ecc/bls12_381/bls12_381_curve.py#L21-L23
    fn prime_group_order() -> num::BigUint {
        BigUint::from_str_radix(
            "52435875175126190479447740508185965837690552500527637822603658699938581184513",
            10,
        )
        .unwrap()
    }

    fn a_int() -> BigUint {
        BigUint::zero()
    }

    fn b_int() -> BigUint {
        BigUint::from(4u32)
    }
}

pub fn bls12381_decompress<E: EllipticCurve>(bytes_be: &[u8], sign_bit: u32) -> AffinePoint<E> {
    let mut g1_bytes_be: [u8; 48] = bytes_be.try_into().unwrap();
    let mut flags = COMPRESSION_FLAG;
    if sign_bit == 1 {
        flags |= Y_IS_ODD_FLAG;
    };

    // set sign and compression flag
    g1_bytes_be[0] |= flags;
    let point = deserialize_g1(&g1_bytes_be).unwrap();

    let x_str = point.getx().to_string();
    let x = BigUint::from_str_radix(x_str.as_str(), 16).unwrap();
    let y_str = point.gety().to_string();
    let y = BigUint::from_str_radix(y_str.as_str(), 16).unwrap();

    AffinePoint::new(x, y)
}

pub fn bls12381_sqrt(a: &BigUint) -> BigUint {
    let a_big = Big::from_bytes(a.to_bytes_be().as_slice());

    let a_sqrt = FP::new_big(a_big).sqrt();

    BigUint::from_str_radix(a_sqrt.to_string().as_str(), 16).unwrap()
}

#[cfg(test)]
mod tests {

    use amcl::bls381::bls381::proof_of_possession::G1_BYTES;

    use super::*;
    use crate::utils::biguint_from_limbs;
    use num::bigint::RandBigInt;
    use rand::thread_rng;

    const NUM_TEST_CASES: usize = 10;

    #[test]
    fn test_weierstrass_biguint_scalar_mul() {
        assert_eq!(biguint_from_limbs(Bls12381BaseField::MODULUS), Bls12381BaseField::modulus());
    }

    #[test]
    fn test_bls12381_decompress() {
        // This test checks that decompression of generator, 2x generator, 4x generator, etc. works.

        // Get the generator point.
        let mut point = {
            let (x, y) = Bls12381Parameters::generator();
            AffinePoint::<SwCurve<Bls12381Parameters>>::new(x, y)
        };
        for _ in 0..NUM_TEST_CASES {
            let (compressed_point, is_odd) = {
                let mut result = [0u8; G1_BYTES];
                let x = point.x.to_bytes_le();
                result[..x.len()].copy_from_slice(&x);
                result.reverse();

                // Evaluate if y > -y
                let y = point.y.clone();
                let y_neg = Bls12381BaseField::modulus() - y.clone();

                // Set flags
                let mut is_odd = 0;
                if y > y_neg {
                    result[0] += Y_IS_ODD_FLAG;
                    is_odd = 1;
                }
                result[0] += COMPRESSION_FLAG;

                (result, is_odd)
            };
            assert_eq!(point, bls12381_decompress(&compressed_point, is_odd));

            // Double the point to create a "random" point for the next iteration.
            point = point.clone().sw_double();
        }
    }

    #[test]
    fn test_bls12381_sqrt() {
        let mut rng = thread_rng();
        for _ in 0..NUM_TEST_CASES {
            // Check that sqrt(x^2)^2 == x^2
            // We use x^2 since not all field elements have a square root
            let x = rng.gen_biguint(256) % Bls12381BaseField::modulus();
            let x_2 = (&x * &x) % Bls12381BaseField::modulus();
            let sqrt = bls12381_sqrt(&x_2);
            let sqrt_2 = (&sqrt * &sqrt) % Bls12381BaseField::modulus();
            assert_eq!(sqrt_2, x_2);
        }
    }
}
