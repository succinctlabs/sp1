use generic_array::GenericArray;
use num::{BigUint, Num, One};
use serde::{Deserialize, Serialize};
use typenum::{U48, U94};

use super::{SwCurve, WeierstrassParameters};
use crate::utils::ec::field::FieldParameters;
use crate::utils::ec::field::NumLimbs;
use crate::utils::ec::EllipticCurveParameters;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Bls12-381 curve parameter
pub struct Bls12381Parameters;

pub type Bls12381 = SwCurve<Bls12381Parameters>;

#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Bls12381 base field parameter
pub struct Bls12381BaseField;

impl FieldParameters for Bls12381BaseField {
    const MODULUS: &'static [u8] = &[
        0xab, 0xaa, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xb9, 0xff, 0xff, 0x53, 0xb1, 0xfe, 0xff, 0xab,
        0x1e, 0x24, 0xf6, 0xb0, 0xf6, 0xa0, 0xd2, 0x30, 0x67, 0xbf, 0x12, 0x85, 0xf3, 0x84, 0x4b,
        0x77, 0x64, 0xd7, 0xac, 0x4b, 0x43, 0xb6, 0xa7, 0x1b, 0x4b, 0x9a, 0xe6, 0x7f, 0x39, 0xea,
        0x11, 0x01, 0x1a,
    ];

    const WITNESS_OFFSET: usize = 1usize << 20;

    fn modulus() -> BigUint {
        BigUint::from_str_radix(
            "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787",
            10,
        )
        .unwrap()
    }
}

impl NumLimbs for Bls12381BaseField {
    type Limbs = U48;
    type Witness = U94;
}

impl EllipticCurveParameters for Bls12381Parameters {
    type BaseField = Bls12381BaseField;
}

impl WeierstrassParameters for Bls12381Parameters {
    const A: GenericArray<u8, U48> = GenericArray::from_array([
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);

    const B: GenericArray<u8, U48> = GenericArray::from_array([
        4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    fn generator() -> (BigUint, BigUint) {
        let x = BigUint::from_str(
            "3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507",
        )
        .unwrap();
        let y = BigUint::from_str(
            "1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569",
        )
        .unwrap();
        (x, y)
    }

    fn prime_group_order() -> num::BigUint {
        BigUint::from_str_radix(
            "52435875175126190479447740508185965837690552500527637822603658699938581184513",
            10,
        )
        .unwrap()
    }

    fn a_int() -> BigUint {
        BigUint::one()
    }

    fn b_int() -> BigUint {
        BigUint::from(4u32)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::utils::ec::utils::biguint_from_limbs;

    #[test]
    fn test_bls12381_modulus() {
        assert_eq!(
            biguint_from_limbs(Bls12381BaseField::MODULUS),
            Bls12381BaseField::modulus()
        );
    }
}
