//! Conversions between `BigUint` and the various concrete big-integer / curve-arithmetic types
//! that the rest of `sp1-curves` uses (`dashu::UBig` for the host-side modular arithmetic in the
//! generic Weierstrass formulas, `k256::U256` for the `k256` fast paths, and `rug::Integer` when
//! the `bigint-rug` feature is on).

use dashu::integer::UBig;
use k256::U256;
use num::BigUint;

pub fn biguint_to_bits_le(integer: &BigUint, num_bits: usize) -> Vec<bool> {
    let byte_vec = integer.to_bytes_le();
    let mut bits = Vec::new();
    for byte in byte_vec {
        for i in 0..8 {
            bits.push(byte & (1 << i) != 0);
        }
    }
    debug_assert!(bits.len() <= num_bits, "Number too large to fit in {num_bits} digits");
    bits.resize(num_bits, false);
    bits
}

pub fn biguint_to_limbs<const N: usize>(integer: &BigUint) -> [u8; N] {
    let mut bytes = integer.to_bytes_le();
    debug_assert!(bytes.len() <= N, "Number too large to fit in {N} limbs");
    bytes.resize(N, 0u8);
    let mut limbs = [0u8; N];
    limbs.copy_from_slice(&bytes);
    limbs
}

#[inline]
pub fn biguint_from_limbs(limbs: &[u8]) -> BigUint {
    BigUint::from_bytes_le(limbs)
}

/// Convert a `BigUint` to a 256-bit `crypto_bigint::U256` (re-exported by `k256` as `k256::U256`).
///
/// Panics in debug mode if the input doesn't fit in 32 bytes; in release mode the upper bits are
/// silently truncated. Use [`biguint_to_limbs`] directly if you want a different word count.
pub fn biguint_to_u256(integer: &BigUint) -> U256 {
    U256::from_le_slice(&biguint_to_limbs::<32>(integer))
}

pub fn biguint_to_dashu(integer: &BigUint) -> UBig {
    UBig::from_le_bytes(integer.to_bytes_le().as_slice())
}

pub fn dashu_to_biguint(integer: &UBig) -> BigUint {
    BigUint::from_bytes_le(&integer.to_le_bytes())
}

pub fn dashu_modpow(base: &UBig, exponent: &UBig, modulus: &UBig) -> UBig {
    if modulus == &UBig::from(1u32) {
        return UBig::from(0u32);
    }

    let mut result = UBig::from(1u32);
    let mut base = base.clone() % modulus;
    let mut exp = exponent.clone();

    while exp > UBig::from(0u32) {
        if &exp % UBig::from(2u32) == UBig::from(1u32) {
            result = (result * &base) % modulus;
        }
        exp >>= 1;
        base = (&base * &base) % modulus;
    }

    result
}

cfg_if::cfg_if! {
    if #[cfg(feature = "bigint-rug")] {
        pub fn biguint_to_rug(integer: &BigUint) -> rug::Integer {
            let mut int = rug::Integer::new();
            unsafe {
                int.assign_bytes_radix_unchecked(integer.to_bytes_be().as_slice(), 256, false);
            }
            int
        }

        pub fn rug_to_biguint(integer: &rug::Integer) -> BigUint {
            let be_bytes = integer.to_digits::<u8>(rug::integer::Order::MsfBe);
            BigUint::from_bytes_be(&be_bytes)
        }
    }
}
