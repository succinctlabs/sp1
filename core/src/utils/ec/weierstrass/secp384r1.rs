//! Modulo defining the Secp384r1 curve and its base field. The constants are all taken from
//! https://www.secg.org/sec2-v2.pdf.

use std::str::FromStr;

use generic_array::GenericArray;
use num::traits::FromBytes;
use num::traits::ToBytes;
use num::BigUint;
use p384::FieldElement;
use serde::{Deserialize, Serialize};
use typenum::{U48, U94};

use super::{SwCurve, WeierstrassParameters};
use crate::operations::field::params::FieldParameters;
use crate::operations::field::params::NumLimbs;
use crate::utils::ec::CurveType;
use crate::utils::ec::EllipticCurveParameters;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Secp384r1 curve parameter
pub struct Secp384r1Parameters;

pub type Secp384r1 = SwCurve<Secp384r1Parameters>;

#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Secp384r1 base field parameter
pub struct Secp384r1BaseField;

impl FieldParameters for Secp384r1BaseField {
    const MODULUS: &'static [u8] = &[
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF,
    ];

    /// A rough witness-offset estimate given the size of the limbs and the size of the field.
    const WITNESS_OFFSET: usize = 1usize << 15;

    fn modulus() -> BigUint {
        BigUint::from_bytes_le(Self::MODULUS)
    }
}

impl NumLimbs for Secp384r1BaseField {
    type Limbs = U48;
    type Witness = U94;
}

impl EllipticCurveParameters for Secp384r1Parameters {
    type BaseField = Secp384r1BaseField;
    const CURVE_TYPE: CurveType = CurveType::Secp384r1;
}

impl WeierstrassParameters for Secp384r1Parameters {
    const A: GenericArray<u8, U48> = GenericArray::from_array([
        252, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 254, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255,
    ]);

    const B: GenericArray<u8, U48> = GenericArray::from_array([
        239, 42, 236, 211, 237, 200, 133, 42, 157, 209, 46, 138, 141, 57, 86, 198, 90, 135, 19, 80,
        143, 8, 20, 3, 18, 65, 129, 254, 110, 156, 29, 24, 25, 45, 248, 227, 107, 5, 142, 152, 228,
        231, 62, 226, 167, 47, 49, 179,
    ]);
    fn generator() -> (BigUint, BigUint) {
        let x = BigUint::from_str(
            "26247035095799689268623156744566981891852923491109213387815615900925518854738050089022388053975719786650872476732087",
        )
        .unwrap();
        let y = BigUint::from_str(
            "8325710961489029985546751289520108179287853048861315594709205902480503199884419224438643760392947333078086511627871",
        )
        .unwrap();
        (x, y)
    }

    fn prime_group_order() -> num::BigUint {
        BigUint::from_slice(&[
            0xCCC52973, 0xECEC196A, 0x48B0A77A, 0x581A0DB2, 0xF4372DDF, 0xC7634D81, 0xFFFFFFFF,
            0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        ])
    }

    fn a_int() -> BigUint {
        BigUint::from_slice(&[
            0xFFFFFFFC, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        ])
    }

    fn b_int() -> BigUint {
        BigUint::from_slice(&[
            0xD3EC2AEF, 0x2A85C8ED, 0x8A2ED19D, 0xC656398D, 0x5013875A, 0x0314088F, 0xFE814112,
            0x181D9C6E, 0xE3F82D19, 0x988E056B, 0xE23EE7E4, 0xB3312FA7,
        ])
    }
}

pub fn secp384r1_sqrt(n: &BigUint) -> BigUint {
    let be_bytes = n.to_be_bytes();
    let mut bytes = [0_u8; 48];
    bytes[48 - be_bytes.len()..].copy_from_slice(&be_bytes);
    let fe = FieldElement::from_bytes(&bytes.into()).unwrap();
    let result_bytes = fe.sqrt().unwrap().to_bytes();
    BigUint::from_be_bytes(&result_bytes as &[u8])
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::utils::ec::utils::biguint_from_limbs;
    use num::bigint::RandBigInt;
    use rand::thread_rng;

    #[test]
    fn test_weierstrass_biguint_scalar_mul_p384() {
        assert_eq!(
            biguint_from_limbs(Secp384r1BaseField::MODULUS),
            Secp384r1BaseField::modulus()
        );
    }

    #[test]
    fn test_secp384r_sqrt() {
        let mut rng = thread_rng();
        for _ in 0..10 {
            // Check that sqrt(x^2)^2 == x^2
            // We use x^2 since not all field elements have a square root
            let x = rng.gen_biguint(256) % Secp384r1BaseField::modulus();
            let x_2 = (&x * &x) % Secp384r1BaseField::modulus();
            let sqrt = secp384r1_sqrt(&x_2);

            println!("sqrt: {}", sqrt);

            let sqrt_2 = (&sqrt * &sqrt) % Secp384r1BaseField::modulus();

            assert_eq!(sqrt_2, x_2);
        }
    }
}
