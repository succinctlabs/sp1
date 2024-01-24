use super::field::NUM_LIMBS;
use num::BigUint;
use num::{One, Zero};

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

/// Computes the difference between `a` and `b` modulo `n`.
pub fn subtract_mod(a: &BigUint, b: &BigUint, n: &BigUint) -> BigUint {
    let a_mod = a % n;
    let b_mod = b % n;
    if a_mod < b_mod {
        (n + a_mod) - b_mod
    } else {
        a_mod - b_mod
    }
}

/// Computes the inverse of `a` modulo `n` using the same idea as the extended Euclidean algorithm.
/// See https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers for details.
pub fn inverse_mod(a: &BigUint, n: &BigUint) -> BigUint {
    let mut t = BigUint::zero();
    let mut new_t = BigUint::one();
    let mut r = n.clone();
    let mut new_r = a.clone();

    while !new_r.is_zero() {
        // The invariant of the loop is that a * t = r (mod n) and a * new_t = new_r (mod n). And
        // new_r is set to r % new_r, so r continues to get smaller and smaller. Therefore, the loop
        // must terminate, and when it terminates we have a * t = 1 (mod n). If r becomes 0 at one
        // point, that implies that a and n had a common factor, which is not allowed.

        let quotient = &r / &new_r;
        (t, new_t) = (new_t.clone(), subtract_mod(&t, &(&quotient * new_t), n));
        (r, new_r) = (new_r.clone(), subtract_mod(&r, &(&quotient * new_r), n));
    }

    assert_eq!(r, BigUint::one(), "a and n must be coprime");

    t
}
