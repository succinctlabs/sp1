//! BabyBear field helpers for R1CS compilation.

/// BabyBear prime: 2^31 - 2^27 + 1 = 2013265921
pub const BABYBEAR_P: u64 = 2013265921;

/// Modulus bits for BabyBear
pub const BABYBEAR_BITS: usize = 31;

/// BabyBear extension field non-residue: u^4 = 11
pub const BABYBEAR_EXT_NR: u64 = 11;

/// Check if a value is in the BabyBear field
pub fn is_valid_babybear(val: u64) -> bool {
    val < BABYBEAR_P
}

/// Compute modular inverse of a in BabyBear field
/// Returns None if a == 0
pub fn babybear_inv(a: u64) -> Option<u64> {
    if a == 0 {
        return None;
    }
    // a^(p-2) mod p
    Some(pow_mod(a, BABYBEAR_P - 2, BABYBEAR_P))
}

/// Compute a^e mod m
fn pow_mod(mut a: u64, mut e: u64, m: u64) -> u64 {
    let mut result = 1u64;
    a %= m;
    while e > 0 {
        if e & 1 == 1 {
            result = (result as u128 * a as u128 % m as u128) as u64;
        }
        e >>= 1;
        a = (a as u128 * a as u128 % m as u128) as u64;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_babybear_inv() {
        // 1^(-1) = 1
        assert_eq!(babybear_inv(1), Some(1));
        
        // 2 * 2^(-1) = 1 mod p
        let inv_2 = babybear_inv(2).unwrap();
        assert_eq!((2u128 * inv_2 as u128) % BABYBEAR_P as u128, 1);
        
        // 0 has no inverse
        assert_eq!(babybear_inv(0), None);
    }
}
