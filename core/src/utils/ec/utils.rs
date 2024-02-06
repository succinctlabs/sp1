use num::BigUint;
use serde::{Deserialize, Serialize};

use crate::operations::field::params::NUM_LIMBS;

use super::field::FieldParameters;

pub fn biguint_to_bits_le(integer: &BigUint, num_bits: usize) -> Vec<bool> {
    let byte_vec = integer.to_bytes_le();
    let mut bits = Vec::new();
    for byte in byte_vec {
        for i in 0..8 {
            bits.push(byte & (1 << i) != 0);
        }
    }
    debug_assert!(
        bits.len() <= num_bits,
        "Number too large to fit in {num_bits} digits"
    );
    bits.resize(num_bits, false);
    bits
}

pub fn biguint_to_limbs(integer: &BigUint) -> [u8; NUM_LIMBS] {
    let mut bytes = integer.to_bytes_le();
    debug_assert!(
        bytes.len() <= NUM_LIMBS,
        "Number too large to fit in {NUM_LIMBS} limbs"
    );
    bytes.resize(NUM_LIMBS, 0u8);
    let mut limbs = [0u8; NUM_LIMBS];
    limbs.copy_from_slice(&bytes);
    limbs
}

#[inline]
pub fn biguint_from_limbs(limbs: &[u8]) -> BigUint {
    BigUint::from_bytes_le(limbs)
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// BabyBear field parameter.
pub struct BabyBearField;

impl FieldParameters for BabyBearField {
    const MODULUS: [u8; NUM_LIMBS] = [
        1, 0, 0, 120, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];

    fn modulus() -> BigUint {
        BigUint::from_bytes_le(&Self::MODULUS)
    }
}
