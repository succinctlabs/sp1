use num::BigUint;

use crate::operations::field::params::NUM_LIMBS;

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
