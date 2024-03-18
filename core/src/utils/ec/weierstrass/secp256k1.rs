//! Modulo defining the Secp256k1 curve and its base field. The constants are all taken from
//! https://en.bitcoin.it/wiki/Secp256k1.

use std::str::FromStr;

use num::{BigUint, Zero};
use serde::{Deserialize, Serialize};

use super::{SwCurve, WeierstrassParameters};
use crate::operations::field::params::{NB_BITS_PER_LIMB, NUM_LIMBS};
use crate::utils::ec::field::{FieldParameters, MAX_NB_LIMBS};
use crate::utils::ec::EllipticCurveParameters;
use k256::FieldElement;
use num::traits::FromBytes;
use num::traits::ToBytes;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Secp256k1 curve parameter
pub struct Secp256k1Parameters;

pub type Secp256k1 = SwCurve<Secp256k1Parameters>;

#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Secp256k1 base field parameter
pub struct Secp256k1BaseField;

impl FieldParameters for Secp256k1BaseField {
    const NB_BITS_PER_LIMB: usize = NB_BITS_PER_LIMB;

    const NB_LIMBS: usize = NUM_LIMBS;

    const NB_WITNESS_LIMBS: usize = 2 * Self::NB_LIMBS - 2;

    const MODULUS: [u8; MAX_NB_LIMBS] = [
        0x2f, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ];

    /// A rough witness-offset estimate given the size of the limbs and the size of the field.
    const WITNESS_OFFSET: usize = 1usize << 14;

    fn modulus() -> BigUint {
        BigUint::from_bytes_le(&Self::MODULUS)
    }
}

impl EllipticCurveParameters for Secp256k1Parameters {
    type BaseField = Secp256k1BaseField;
    const NAME: &'static str = "secp256k1";
}

impl WeierstrassParameters for Secp256k1Parameters {
    const A: [u16; MAX_NB_LIMBS] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];

    const B: [u16; MAX_NB_LIMBS] = [
        7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
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

pub fn secp256k1_sqrt(n: &BigUint) -> BigUint {
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
    use crate::utils::ec::utils::biguint_from_limbs;
    use num::bigint::RandBigInt;
    use rand::thread_rng;

    #[test]
    fn test_weierstrass_biguint_scalar_mul() {
        assert_eq!(
            biguint_from_limbs(&Secp256k1BaseField::MODULUS),
            Secp256k1BaseField::modulus()
        );
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
            if sqrt > x_2 {
                println!("wtf");
            }

            let sqrt_2 = (&sqrt * &sqrt) % Secp256k1BaseField::modulus();

            assert_eq!(sqrt_2, x_2);
        }
    }
}
