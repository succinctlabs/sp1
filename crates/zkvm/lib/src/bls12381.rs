use std::io::ErrorKind;

use crate::{
    syscall_bls12381_add, syscall_bls12381_double,
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

/// Decompresses a compressed public key using bls12381_decompress precompile.
///
/// # Deprecated
///
/// The `BLS12381_DECOMPRESS` precompile is decommissioned: it has no executor implementation
/// and no AIR, so every call traps the executor regardless of input. There is no compressed
/// key for which this function returns.
///
/// Independently of that, this function does not validate the key it is named for: the
/// point-at-infinity flag is discarded rather than inspected, no r-order subgroup check is
/// performed, and the `Result` is never `Err`. Those defects are dormant only because the
/// precompile is unreachable; see <https://github.com/succinctlabs/sp1/issues/2927>. Do not
/// treat a future reinstatement of the precompile as making this function safe to use for key
/// validation without first addressing them.
#[deprecated = "the BLS12381_DECOMPRESS precompile is decommissioned (no executor \
                implementation, no AIR); every call traps the executor. This function also \
                performs no key validation. See \
                https://github.com/succinctlabs/sp1/issues/2926"]
pub fn decompress_pubkey(compressed_key: &[u64; 6]) -> Result<[u64; 12], ErrorKind> {
    let mut decompressed_key = [0u64; 12];
    decompressed_key[..6].copy_from_slice(compressed_key);

    // The sign bit is stored in the first byte, so we have to access it like this.
    let mut decompressed_key = decompressed_key.map(u64::to_ne_bytes);

    // The sign bit is the third most significant bit (beginning the count at "first").
    const SIGN_OFFSET: u32 = 3;
    const SIGN_MASK: u8 = 1u8 << (u8::BITS - SIGN_OFFSET);
    let sign_bit = (decompressed_key[0][0] & SIGN_MASK) != 0;
    decompressed_key[0][0] <<= SIGN_OFFSET;
    decompressed_key[0][0] >>= SIGN_OFFSET;

    let mut decompressed_key = decompressed_key.map(u64::from_ne_bytes);

    // The syscall carries the same deprecation as this function; the call is what makes this
    // function deprecated in the first place. Called by path rather than imported so that a
    // single `allow` covers it.
    #[allow(deprecated)]
    unsafe {
        crate::syscall_bls12381_decompress(&mut decompressed_key, sign_bit);
    }

    Ok(decompressed_key)
}
