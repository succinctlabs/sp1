use generic_array::GenericArray;
use num::{BigUint, Num, Zero};
use serde::{Deserialize, Serialize};
use typenum::{U48, U94};

use super::{SwCurve, WeierstrassParameters};
use crate::utils::ec::field::FieldParameters;
use crate::utils::ec::field::NumLimbs;
use crate::utils::ec::CurveType;
use crate::utils::ec::EllipticCurveParameters;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Bls12-381 curve parameter
pub struct Bls12381Parameters;

pub type Bls12381 = SwCurve<Bls12381Parameters>;

#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Bls12381 base field parameter
pub struct Bls12381BaseField;

impl FieldParameters for Bls12381BaseField {
    // The modulus has been taken from py_ecc python library by Ethereum Foundation.
    // // https://github.com/ethereum/py_ecc/blob/7b9e1b3/py_ecc/fields/field_properties.py#L30
    // The below value is the little-endian representation of the modulus.
    const MODULUS: &'static [u8] = &[
        171, 170, 255, 255, 255, 255, 254, 185, 255, 255, 83, 177, 254, 255, 171, 30, 36, 246, 176,
        246, 160, 210, 48, 103, 191, 18, 133, 243, 132, 75, 119, 100, 215, 172, 75, 67, 182, 167,
        27, 75, 154, 230, 127, 57, 234, 17, 1, 26,
    ];

    // A rough witness-offset estimate given the size of the limbs and the size of the field.
    const WITNESS_OFFSET: usize = 1usize << 13;

    // The modulus has been taken from py_ecc python library by Ethereum Foundation.
    // https://github.com/ethereum/py_ecc/blob/7b9e1b3/py_ecc/fields/field_properties.py#L30
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

    // The generator has been taken from py_ecc python library by Ethereum Foundation.
    // https://github.com/ethereum/py_ecc/blob/7b9e1b3/py_ecc/bls12_381/bls12_381_curve.py#L38-L45
    fn generator() -> (BigUint, BigUint) {
        let x = BigUint::from_str_radix(
            "3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507", 10
        )
        .unwrap();
        let y = BigUint::from_str_radix(
            "1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569", 10
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
