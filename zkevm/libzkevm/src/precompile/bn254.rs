//! BN254 precompiles — Ethereum 0x06, 0x07, 0x08 (EIP-196 / EIP-197).
//!
//! Wraps the patched `substrate-bn` crate. At `target_os = "zkvm"` curve
//! and Fp/Fp2 arithmetic route through SP1's `BN254_*` precompile
//! syscalls; on host it falls back to the software pure-Rust path.
//!
//! Layout per `zkvm_accelerators.h`: G1 = 64 bytes (x || y) big-endian,
//! G2 = 128 bytes (x.a1 || x.a0 || y.a1 || y.a0) big-endian per EIP-197,
//! and `(0, 0)` denotes the point at infinity.

use crate::precompile::types::{Bn254G1Point, Bn254PairingPair, Bn254Scalar};
use crate::status::{ZKVM_EFAIL, ZKVM_EOK};
use substrate_bn::{pairing_batch, AffineG1, AffineG2, Fq, Fq2, Fr, Group, Gt, G1, G2};

fn fq_from_be(bytes: &[u8]) -> Option<Fq> {
    Fq::from_slice(bytes).ok()
}

/// Decode a 64-byte EIP-196 G1 point. `(0, 0)` decodes to the point at
/// infinity (`G1::zero()`). Returns `None` if the field elements are
/// out-of-range or `(x, y)` is not on the curve.
fn decode_g1(bytes: &[u8; 64]) -> Option<G1> {
    if bytes.iter().all(|&b| b == 0) {
        return Some(G1::zero());
    }
    let x = fq_from_be(&bytes[0..32])?;
    let y = fq_from_be(&bytes[32..64])?;
    AffineG1::new(x, y).ok().map(Into::into)
}

/// Decode a 128-byte EIP-197 G2 point. Coordinate ordering matches
/// EIP-197: `(x.a1 || x.a0 || y.a1 || y.a0)`. `(0, 0, 0, 0)` is the
/// point at infinity.
fn decode_g2(bytes: &[u8; 128]) -> Option<G2> {
    if bytes.iter().all(|&b| b == 0) {
        return Some(G2::zero());
    }
    let x_a1 = fq_from_be(&bytes[0..32])?;
    let x_a0 = fq_from_be(&bytes[32..64])?;
    let y_a1 = fq_from_be(&bytes[64..96])?;
    let y_a0 = fq_from_be(&bytes[96..128])?;
    let x = Fq2::new(x_a0, x_a1);
    let y = Fq2::new(y_a0, y_a1);
    AffineG2::new(x, y).ok().map(Into::into)
}

/// Encode a `G1` point as 64 BE bytes (`x || y`); the point at infinity
/// is encoded as all zeros per EIP-196.
fn encode_g1(p: G1, out: &mut [u8; 64]) {
    *out = [0u8; 64];
    let affine: Option<AffineG1> = AffineG1::from_jacobian(p);
    if let Some(a) = affine {
        // `to_big_endian` only fails on a too-short slice; 32 bytes is correct.
        let _ = a.x().to_big_endian(&mut out[0..32]);
        let _ = a.y().to_big_endian(&mut out[32..64]);
    }
}

/// `zkvm_status zkvm_bn254_g1_add(p1, p2, result)`.
#[no_mangle]
pub unsafe extern "C" fn zkvm_bn254_g1_add(
    p1: *const Bn254G1Point,
    p2: *const Bn254G1Point,
    result: *mut Bn254G1Point,
) -> i32 {
    if p1.is_null() || p2.is_null() || result.is_null() {
        return ZKVM_EFAIL;
    }
    let a = match decode_g1(&(*p1).data) {
        Some(p) => p,
        None => return ZKVM_EFAIL,
    };
    let b = match decode_g1(&(*p2).data) {
        Some(p) => p,
        None => return ZKVM_EFAIL,
    };
    encode_g1(a + b, &mut (*result).data);
    ZKVM_EOK
}

/// `zkvm_status zkvm_bn254_g1_mul(point, scalar, result)`.
///
/// Scalar is a 32-byte big-endian integer; substrate-bn reduces it
/// modulo the group order via `Fr::from_bytes_be_mod_order`.
#[no_mangle]
pub unsafe extern "C" fn zkvm_bn254_g1_mul(
    point: *const Bn254G1Point,
    scalar: *const Bn254Scalar,
    result: *mut Bn254G1Point,
) -> i32 {
    if point.is_null() || scalar.is_null() || result.is_null() {
        return ZKVM_EFAIL;
    }
    let p = match decode_g1(&(*point).data) {
        Some(p) => p,
        None => return ZKVM_EFAIL,
    };
    let s = match Fr::from_bytes_be_mod_order(&(*scalar).data) {
        Ok(s) => s,
        Err(_) => return ZKVM_EFAIL,
    };
    encode_g1(p * s, &mut (*result).data);
    ZKVM_EOK
}

/// `zkvm_status zkvm_bn254_pairing(pairs, num_pairs, verified)`.
///
/// Computes `Π e(p_i.g1, p_i.g2)` and writes `*verified = (product == 1)`.
/// Empty input verifies as `true` per EIP-197.
#[no_mangle]
pub unsafe extern "C" fn zkvm_bn254_pairing(
    pairs: *const Bn254PairingPair,
    num_pairs: usize,
    verified: *mut bool,
) -> i32 {
    if (pairs.is_null() && num_pairs != 0) || verified.is_null() {
        return ZKVM_EFAIL;
    }
    let mut decoded = alloc::vec::Vec::with_capacity(num_pairs);
    for i in 0..num_pairs {
        let pair = &*pairs.add(i);
        let g1 = match decode_g1(&pair.g1.data) {
            Some(p) => p,
            None => return ZKVM_EFAIL,
        };
        let g2 = match decode_g2(&pair.g2.data) {
            Some(p) => p,
            None => return ZKVM_EFAIL,
        };
        decoded.push((g1, g2));
    }
    let product = pairing_batch(&decoded);
    *verified = product == Gt::one();
    ZKVM_EOK
}
