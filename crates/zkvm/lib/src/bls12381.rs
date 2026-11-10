use std::io::ErrorKind;

use crate::{
    syscall_bls12381_add, syscall_bls12381_decompress, syscall_bls12381_double,
    utils::{AffinePoint, WeierstrassAffinePoint, WeierstrassPoint},
};

/// The number of limbs in [Bls12381AffinePoint].
pub const N: usize = 12;

/// A point on the BLS12-381 curve.
#[derive(Copy, Clone)]
#[repr(align(8))]
pub struct Bls12381Point(pub WeierstrassPoint<N>);

impl WeierstrassAffinePoint<N> for Bls12381Point {
    fn infinity() -> Self {
        Self(WeierstrassPoint::Infinity)
    }

    fn is_infinity(&self) -> bool {
        matches!(self.0, WeierstrassPoint::Infinity)
    }
}

impl AffinePoint<N> for Bls12381Point {
    const GENERATOR: [u64; N] = [
        18103045581585958587,
        7806400890582735599,
        11623291730934869080,
        14080658508445169925,
        2780237799254240271,
        1725392847304644500,
        912580534683953121,
        15005087156090211044,
        61670280795567085,
        18227722000993880822,
        11573741888802228964,
        627113611842199793,
    ];

    /// The generator was taken from "py_ecc" python library by the Ethereum Foundation:
    ///
    /// https://github.com/ethereum/py_ecc/blob/7b9e1b3/py_ecc/bls12_381/bls12_381_curve.py#L38-L45
    #[allow(deprecated)]
    const GENERATOR_T: Self = Self(WeierstrassPoint::Affine(Self::GENERATOR));

    fn new(limbs: [u64; N]) -> Self {
        Self(WeierstrassPoint::Affine(limbs))
    }

    fn identity() -> Self {
        Self::infinity()
    }

    fn is_identity(&self) -> bool {
        self.is_infinity()
    }

    fn limbs_ref(&self) -> &[u64; N] {
        match &self.0 {
            WeierstrassPoint::Infinity => panic!("Infinity point has no limbs"),
            WeierstrassPoint::Affine(limbs) => limbs,
        }
    }

    fn limbs_mut(&mut self) -> &mut [u64; N] {
        match &mut self.0 {
            WeierstrassPoint::Infinity => panic!("Infinity point has no limbs"),
            WeierstrassPoint::Affine(limbs) => limbs,
        }
    }

    fn add_assign(&mut self, other: &Self) {
        let a = self.limbs_mut();
        let b = other.limbs_ref();
        unsafe {
            syscall_bls12381_add(a, b);
        }
    }

    fn complete_add_assign(&mut self, other: &Self) {
        self.weierstrass_add_assign(other);
    }

    fn double(&mut self) {
        let a = self.limbs_mut();
        unsafe {
            syscall_bls12381_double(a);
        }
    }
}

impl Bls12381Point {
    /// Decompresses a compressed G1 point into a `Bls12381Point`.
    ///
    /// If the canonical infinity encoding (`0xc0` followed by 47 zero bytes) is provided,
    /// returns `Ok(Bls12381Point::infinity())`.
    pub fn from_compressed(compressed_key: &[u64; 6]) -> Result<Self, ErrorKind> {
        let raw_bytes = compressed_key.map(u64::to_ne_bytes);
        let leading_byte = raw_bytes[0][0];

        const COMPRESSION_FLAG: u8 = 1u8 << 7;
        const INFINITY_FLAG: u8 = 1u8 << 6;
        const SIGN_FLAG: u8 = 1u8 << 5;

        if (leading_byte & COMPRESSION_FLAG) == 0 {
            return Err(ErrorKind::InvalidInput);
        }

        if (leading_byte & INFINITY_FLAG) != 0 {
            if (leading_byte & SIGN_FLAG) != 0 || (leading_byte & 0x1F) != 0 {
                return Err(ErrorKind::InvalidData);
            }
            for (i, word) in raw_bytes.iter().enumerate() {
                let start_idx = if i == 0 { 1 } else { 0 };
                if word[start_idx..].iter().any(|&b| b != 0) {
                    return Err(ErrorKind::InvalidData);
                }
            }
            return Ok(Self::infinity());
        }

        let decompressed = decompress_pubkey(compressed_key)?;
        Ok(Self::new(decompressed))
    }
}

/// Decompresses a compressed public key using bls12381_decompress precompile.
///
/// Validates that the input is in compressed format and rejects the identity/infinity point,
/// which is forbidden as a public key under IETF BLS signature specifications (RFC 9380).
pub fn decompress_pubkey(compressed_key: &[u64; 6]) -> Result<[u64; 12], ErrorKind> {
    let mut decompressed_key = [0u64; 12];
    decompressed_key[..6].copy_from_slice(compressed_key);

    let mut decompressed_key_bytes = decompressed_key.map(u64::to_ne_bytes);
    let leading_byte = decompressed_key_bytes[0][0];

    const COMPRESSION_FLAG: u8 = 1u8 << 7; // 0x80
    const INFINITY_FLAG: u8 = 1u8 << 6;    // 0x40
    const SIGN_FLAG: u8 = 1u8 << 5;        // 0x20

    // Compressed flag must be set for a compressed public key.
    if (leading_byte & COMPRESSION_FLAG) == 0 {
        return Err(ErrorKind::InvalidInput);
    }

    // Rejection of point-at-infinity per IETF BLS KeyValidate specification:
    // Identity public key has e(∞, H(m)) = 1, which trivially satisfies pairing verification for any message.
    if (leading_byte & INFINITY_FLAG) != 0 {
        // Validate canonical infinity encoding before rejecting:
        // non-flag bits must be 0, sign bit must be 0, and all remaining 47 bytes must be zero.
        if (leading_byte & SIGN_FLAG) != 0 || (leading_byte & 0x1F) != 0 {
            return Err(ErrorKind::InvalidData);
        }
        for (i, word) in decompressed_key_bytes.iter().take(6).enumerate() {
            let start = if i == 0 { 1 } else { 0 };
            if word[start..].iter().any(|&b| b != 0) {
                return Err(ErrorKind::InvalidData);
            }
        }
        return Err(ErrorKind::InvalidInput);
    }

    let sign_bit = (leading_byte & SIGN_FLAG) != 0;
    decompressed_key_bytes[0][0] &= 0x1F;

    let mut decompressed_key = decompressed_key_bytes.map(u64::from_ne_bytes);

    unsafe {
        syscall_bls12381_decompress(&mut decompressed_key, sign_bit);
    }

    Ok(decompressed_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[no_mangle]
    extern "C" fn syscall_bls12381_decompress(_point: &mut [u64; 12], _is_odd: bool) {}

    #[test]
    fn test_canonical_infinity_rejected_for_pubkey() {
        // Canonical compressed G1 infinity encoding:
        // Leading byte 0xc0 (compression flag 0x80 | infinity flag 0x40), followed by 47 zero bytes.
        let mut raw = [[0u8; 8]; 6];
        raw[0][0] = 0xc0;
        let compressed = raw.map(u64::from_ne_bytes);

        // Pubkey validation must reject infinity point (identity element)
        let res = decompress_pubkey(&compressed);
        assert_eq!(res.unwrap_err(), ErrorKind::InvalidInput);
    }

    #[test]
    fn test_canonical_infinity_accepted_by_from_compressed() {
        let mut raw = [[0u8; 8]; 6];
        raw[0][0] = 0xc0;
        let compressed = raw.map(u64::from_ne_bytes);

        let point = Bls12381Point::from_compressed(&compressed).unwrap();
        assert!(point.is_infinity());
    }

    #[test]
    fn test_invalid_infinity_with_sign_or_data_rejected() {
        // Non-canonical infinity: sign bit set (0xe0)
        let mut raw = [[0u8; 8]; 6];
        raw[0][0] = 0xe0;
        let compressed = raw.map(u64::from_ne_bytes);

        let res = decompress_pubkey(&compressed);
        assert_eq!(res.unwrap_err(), ErrorKind::InvalidData);

        // Non-canonical infinity: non-zero byte in x coordinate
        let mut raw = [[0u8; 8]; 6];
        raw[0][0] = 0xc0;
        raw[0][1] = 0x01;
        let compressed = raw.map(u64::from_ne_bytes);

        let res = decompress_pubkey(&compressed);
        assert_eq!(res.unwrap_err(), ErrorKind::InvalidData);
    }

    #[test]
    fn test_uncompressed_input_rejected() {
        // Leading byte missing compression flag 0x80
        let compressed = [0u64; 6];
        let res = decompress_pubkey(&compressed);
        assert_eq!(res.unwrap_err(), ErrorKind::InvalidInput);
    }
}
