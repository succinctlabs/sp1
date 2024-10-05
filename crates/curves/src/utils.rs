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

/// Memoize a BigUint from a slice of limbs.
///
/// See: [biguint_from_limbs]
macro_rules! memo_big_uint_limbs {
    ($limbs:expr) => {{
        static _MEMO_TEMP: std::sync::OnceLock<::num::BigUint> = std::sync::OnceLock::new();

        _MEMO_TEMP.get_or_init(|| $crate::utils::biguint_from_limbs($limbs))
    }};
}

/// Memoize a BigUint from a const string, you can optionally pass a radix.
///
/// ```ignore
///     let t = memo_big_uint_str!("1234567890");
///     let t = memo_big_uint_str!("1234567890", 16);
/// ```
macro_rules! memo_big_uint_str {
    ($uint:expr, $radix:expr) => {{
        static _MEMO_TEMP: std::sync::OnceLock<::num::BigUint> = std::sync::OnceLock::new();

        _MEMO_TEMP.get_or_init(|| ::num::BigUint::from_str_radix($uint, $radix).unwrap())
    }};
    ($uint:expr) => {{
        use std::str::FromStr;

        static _MEMO_TEMP: std::sync::OnceLock<::num::BigUint> = std::sync::OnceLock::new();

        _MEMO_TEMP.get_or_init(|| ::num::BigUint::from_str($uint).unwrap())
    }};
}

pub(crate) use memo_big_uint_limbs;
pub(crate) use memo_big_uint_str;
