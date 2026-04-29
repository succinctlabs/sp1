//! BLS12-381 precompiles — Ethereum 0x0b..0x11 (EIP-2537).
//!
//! Wraps the patched `bls12_381` crate. Layout per
//! `zkvm_accelerators.h`: G1 = 96 bytes (Fp x || Fp y, BE), G2 = 192
//! bytes (Fp2 x || Fp2 y, BE; Fp2 = c1 || c0). Scalar = 32 BE bytes.

use crate::ecall;
use crate::precompile::types::{
    Bls12381Fp, Bls12381Fp2, Bls12381G1MsmPair, Bls12381G1Point, Bls12381G2MsmPair,
    Bls12381G2Point, Bls12381PairingPair,
};
use crate::status::{ZKVM_EFAIL, ZKVM_EOK};
use bls12_381::{
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar,
};

fn decode_g1(bytes: &[u8; 96]) -> Option<G1Affine> {
    G1Affine::from_uncompressed(bytes).into_option()
}

fn decode_g2(bytes: &[u8; 192]) -> Option<G2Affine> {
    G2Affine::from_uncompressed(bytes).into_option()
}

fn encode_g1(p: G1Projective, out: &mut [u8; 96]) {
    *out = G1Affine::from(p).to_uncompressed();
}

fn encode_g2(p: G2Projective, out: &mut [u8; 192]) {
    *out = G2Affine::from(p).to_uncompressed();
}

/// Decode a 32-byte big-endian integer into a `Scalar`, reducing modulo
/// the BLS12-381 group order via `Scalar::from_bytes_wide` (zero-pad to
/// 64 bytes; that constructor reduces).
fn decode_scalar(bytes: &[u8; 32]) -> Scalar {
    let mut le = [0u8; 64];
    for (i, b) in bytes.iter().rev().enumerate() {
        le[i] = *b;
    }
    Scalar::from_bytes_wide(&le)
}

#[no_mangle]
pub unsafe extern "C" fn zkvm_bls12_g1_add(
    p1: *const Bls12381G1Point,
    p2: *const Bls12381G1Point,
    result: *mut Bls12381G1Point,
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
    encode_g1(G1Projective::from(a) + G1Projective::from(b), &mut (*result).data);
    ZKVM_EOK
}

#[no_mangle]
pub unsafe extern "C" fn zkvm_bls12_g1_msm(
    pairs: *const Bls12381G1MsmPair,
    num_pairs: usize,
    result: *mut Bls12381G1Point,
) -> i32 {
    if (pairs.is_null() && num_pairs != 0) || result.is_null() {
        return ZKVM_EFAIL;
    }
    let mut acc = G1Projective::identity();
    for i in 0..num_pairs {
        let pair = &*pairs.add(i);
        let pt = match decode_g1(&pair.point.data) {
            Some(p) => p,
            None => return ZKVM_EFAIL,
        };
        let s = decode_scalar(&pair.scalar.data);
        acc += G1Projective::from(pt) * s;
    }
    encode_g1(acc, &mut (*result).data);
    ZKVM_EOK
}

#[no_mangle]
pub unsafe extern "C" fn zkvm_bls12_g2_add(
    p1: *const Bls12381G2Point,
    p2: *const Bls12381G2Point,
    result: *mut Bls12381G2Point,
) -> i32 {
    if p1.is_null() || p2.is_null() || result.is_null() {
        return ZKVM_EFAIL;
    }
    let a = match decode_g2(&(*p1).data) {
        Some(p) => p,
        None => return ZKVM_EFAIL,
    };
    let b = match decode_g2(&(*p2).data) {
        Some(p) => p,
        None => return ZKVM_EFAIL,
    };
    encode_g2(G2Projective::from(a) + G2Projective::from(b), &mut (*result).data);
    ZKVM_EOK
}

#[no_mangle]
pub unsafe extern "C" fn zkvm_bls12_g2_msm(
    pairs: *const Bls12381G2MsmPair,
    num_pairs: usize,
    result: *mut Bls12381G2Point,
) -> i32 {
    if (pairs.is_null() && num_pairs != 0) || result.is_null() {
        return ZKVM_EFAIL;
    }
    let mut acc = G2Projective::identity();
    for i in 0..num_pairs {
        let pair = &*pairs.add(i);
        let pt = match decode_g2(&pair.point.data) {
            Some(p) => p,
            None => return ZKVM_EFAIL,
        };
        let s = decode_scalar(&pair.scalar.data);
        acc += G2Projective::from(pt) * s;
    }
    encode_g2(acc, &mut (*result).data);
    ZKVM_EOK
}

#[no_mangle]
pub unsafe extern "C" fn zkvm_bls12_pairing(
    pairs: *const Bls12381PairingPair,
    num_pairs: usize,
    verified: *mut bool,
) -> i32 {
    if (pairs.is_null() && num_pairs != 0) || verified.is_null() {
        return ZKVM_EFAIL;
    }
    let mut g1s = alloc::vec::Vec::with_capacity(num_pairs);
    let mut g2s = alloc::vec::Vec::with_capacity(num_pairs);
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
        g1s.push(g1);
        g2s.push(G2Prepared::from(g2));
    }
    let terms: alloc::vec::Vec<_> = g1s.iter().zip(g2s.iter()).collect();
    let result = multi_miller_loop(&terms).final_exponentiation();
    *verified = result == Gt::identity();
    ZKVM_EOK
}

/// SP1 has no precompile yet for the SSWU map; would need software
/// `map_to_curve` + clear-cofactor over the patched Fp ops. Stub for now.
#[no_mangle]
pub unsafe extern "C" fn zkvm_bls12_map_fp_to_g1(
    field_element: *const Bls12381Fp,
    result: *mut Bls12381G1Point,
) -> i32 {
    if field_element.is_null() || result.is_null() {
        return ZKVM_EFAIL;
    }
    ecall::ecall2(
        ecall::placeholder::TODO_BLS12_MAP_FP_TO_G1,
        field_element as usize,
        result as usize,
    );
    ZKVM_EFAIL
}

#[no_mangle]
pub unsafe extern "C" fn zkvm_bls12_map_fp2_to_g2(
    field_element: *const Bls12381Fp2,
    result: *mut Bls12381G2Point,
) -> i32 {
    if field_element.is_null() || result.is_null() {
        return ZKVM_EFAIL;
    }
    ecall::ecall2(
        ecall::placeholder::TODO_BLS12_MAP_FP2_TO_G2,
        field_element as usize,
        result as usize,
    );
    ZKVM_EFAIL
}
