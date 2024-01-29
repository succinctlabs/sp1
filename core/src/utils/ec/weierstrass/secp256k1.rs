use num::{BigUint, Num, Zero};
use serde::{Deserialize, Serialize};

use super::{SWCurve, WeierstrassParameters};
use crate::utils::ec::field::{FieldParameters, MAX_NB_LIMBS};
use crate::utils::ec::EllipticCurveParameters;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Secp256k1 curve parameter
pub struct Secp256k1Parameters;

pub type Secp256k1 = SWCurve<Secp256k1Parameters>;

#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Secp256k1 base field parameter
pub struct Secp256k1BaseField;

impl FieldParameters for Secp256k1BaseField {
    // TODO: The parameters are all wrong, I just copied and pasted them from bn254.rs.
    const NB_BITS_PER_LIMB: usize = 16;

    const NB_LIMBS: usize = 16;

    const NB_WITNESS_LIMBS: usize = 2 * Self::NB_LIMBS - 2;

    const MODULUS: [u8; MAX_NB_LIMBS] = [
        0x2f, 0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ];

    const WITNESS_OFFSET: usize = 1usize << 20;

    fn modulus() -> BigUint {
        BigUint::from_slice(&[
            0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF,
        ])
    }
}

impl EllipticCurveParameters for Secp256k1Parameters {
    type BaseField = Secp256k1BaseField;
}

impl WeierstrassParameters for Secp256k1Parameters {
    // TODO: These are all wrong, I just copied and pasted it from bn245.rs.
    const A: [u16; MAX_NB_LIMBS] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];

    const B: [u16; MAX_NB_LIMBS] = [
        3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    fn generator() -> (BigUint, BigUint) {
        let x = BigUint::from(1u32);
        let y = BigUint::from(2u32);
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
        BigUint::from(3u32)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::utils::ec::utils::biguint_from_limbs;

    #[test]
    fn test_weierstrass_biguint_scalar_mul() {
        assert_eq!(
            biguint_from_limbs(&Secp256k1BaseField::MODULUS),
            Secp256k1BaseField::modulus()
        );
    }
}
