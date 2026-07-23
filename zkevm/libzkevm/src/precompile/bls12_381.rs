//! BLS12-381 precompiles — Ethereum 0x0b..0x11 (EIP-2537).
//!
//! Wraps the patched `bls12_381` crate. Layout per
//! `zkvm_accelerators.h`: G1 = 96 bytes (Fp x || Fp y, BE), G2 = 192
//! bytes (Fp2 x || Fp2 y, BE; Fp2 = c0 || c1). Scalar = 32 BE bytes.

use crate::precompile::types::{
    Bls12381Fp, Bls12381Fp2, Bls12381G1MsmPair, Bls12381G1Point, Bls12381G2MsmPair,
    Bls12381G2Point, Bls12381PairingPair,
};
use crate::status::{ZKVM_EFAIL, ZKVM_EOK};
use bls12_381::hash_to_curve::MapToCurve;
use bls12_381::{
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar,
};

/// The bls12_381's uncompressed point-at-infinity marker, bit 6 of byte 0.
const INFINITY_FLAG: u8 = 1 << 6;

/// EIP-2537 G1 (infinity = all zeros) to crate uncompressed (bit-6 flag).
fn g1_from_abi(bytes: &[u8; 96]) -> [u8; 96] {
    if bytes.iter().all(|&b| b == 0) {
        let mut out = [0u8; 96];
        out[0] = INFINITY_FLAG;
        out
    } else {
        *bytes
    }
}

/// Inverse of [`g1_from_abi`] for results.
fn g1_to_abi(bytes: [u8; 96]) -> [u8; 96] {
    if bytes[0] & INFINITY_FLAG != 0 {
        [0u8; 96]
    } else {
        bytes
    }
}

/// Swaps the c0 and c1 halves of each Fp2 coordinate; its own inverse.
fn g2_swap_c0c1(bytes: &[u8; 192]) -> [u8; 192] {
    let mut out = [0u8; 192];
    out[0..48].copy_from_slice(&bytes[48..96]);
    out[48..96].copy_from_slice(&bytes[0..48]);
    out[96..144].copy_from_slice(&bytes[144..192]);
    out[144..192].copy_from_slice(&bytes[96..144]);
    out
}

/// EIP-2537 G2 (c0 || c1, infinity = all zeros) to crate (c1 || c0, bit-6 flag).
fn g2_from_abi(bytes: &[u8; 192]) -> [u8; 192] {
    if bytes.iter().all(|&b| b == 0) {
        let mut out = [0u8; 192];
        out[0] = INFINITY_FLAG;
        out
    } else {
        g2_swap_c0c1(bytes)
    }
}

/// Inverse of [`g2_from_abi`] for results.
fn g2_to_abi(bytes: [u8; 192]) -> [u8; 192] {
    if bytes[0] & INFINITY_FLAG != 0 {
        [0u8; 192]
    } else {
        g2_swap_c0c1(&bytes)
    }
}

/// Rejects coordinates carrying the crate's flag bits (values >= p): the crate
/// masks them on the first coordinate and would accept `0x40||00..` as infinity.
fn is_canonical_coords(bytes: &[u8]) -> bool {
    bytes.chunks_exact(48).all(|coord| coord[0] & 0b1110_0000 == 0)
}

/// Full decode for MSM and pairing (precompiles 0x0c/0x0e/0x0f), where
/// EIP-2537 requires the subgroup check in addition to the on-curve check.
fn decode_g1(bytes: &[u8; 96]) -> Option<G1Affine> {
    if !is_canonical_coords(bytes) {
        return None;
    }
    G1Affine::from_uncompressed(&g1_from_abi(bytes)).into_option()
}

/// See [`decode_g1`].
fn decode_g2(bytes: &[u8; 192]) -> Option<G2Affine> {
    if !is_canonical_coords(bytes) {
        return None;
    }
    G2Affine::from_uncompressed(&g2_from_abi(bytes)).into_option()
}

/// Decode for G1ADD (precompile 0x0b): encoding, field-element, and
/// on-curve validation, but NOT the subgroup check — EIP-2537 explicitly
/// omits it for addition, and its test vectors include on-curve points
/// outside the q-order subgroup that G1ADD must accept.
fn decode_g1_on_curve(bytes: &[u8; 96]) -> Option<G1Affine> {
    if !is_canonical_coords(bytes) {
        return None;
    }
    let p = G1Affine::from_uncompressed_unchecked(&g1_from_abi(bytes)).into_option()?;
    bool::from(p.is_on_curve()).then_some(p)
}

/// See [`decode_g1_on_curve`]; this is the G2ADD (precompile 0x0d) variant.
fn decode_g2_on_curve(bytes: &[u8; 192]) -> Option<G2Affine> {
    if !is_canonical_coords(bytes) {
        return None;
    }
    let p = G2Affine::from_uncompressed_unchecked(&g2_from_abi(bytes)).into_option()?;
    bool::from(p.is_on_curve()).then_some(p)
}

fn encode_g1(p: G1Projective, out: &mut [u8; 96]) {
    *out = g1_to_abi(G1Affine::from(p).to_uncompressed());
}

fn encode_g2(p: G2Projective, out: &mut [u8; 192]) {
    *out = g2_to_abi(G2Affine::from(p).to_uncompressed());
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
    let a = match decode_g1_on_curve(&(*p1).data) {
        Some(p) => p,
        None => return ZKVM_EFAIL,
    };
    let b = match decode_g1_on_curve(&(*p2).data) {
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
    let a = match decode_g2_on_curve(&(*p1).data) {
        Some(p) => p,
        None => return ZKVM_EFAIL,
    };
    let b = match decode_g2_on_curve(&(*p2).data) {
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
        // Skip pair with either point at infinity (which contributes e = 1).
        if bool::from(g1.is_identity()) || bool::from(g2.is_identity()) {
            continue;
        }
        g1s.push(g1);
        g2s.push(G2Prepared::from(g2));
    }
    let terms: alloc::vec::Vec<_> = g1s.iter().zip(g2s.iter()).collect();
    let result = multi_miller_loop(&terms).final_exponentiation();
    *verified = result == Gt::identity();
    ZKVM_EOK
}

fn fp_from_be(bytes: &[u8; 48]) -> Option<bls12_381::fp::Fp> {
    bls12_381::fp::Fp::from_bytes(bytes).into_option()
}

/// `zkvm_status zkvm_bls12_map_fp_to_g1(...)` — Ethereum precompile 0x10
/// (EIP-2537). Maps an Fp element to G1 via the SWU base map and clears
/// the cofactor (multiply by `1 - z`).
#[no_mangle]
pub unsafe extern "C" fn zkvm_bls12_map_fp_to_g1(
    field_element: *const Bls12381Fp,
    result: *mut Bls12381G1Point,
) -> i32 {
    if field_element.is_null() || result.is_null() {
        return ZKVM_EFAIL;
    }
    let fp = match fp_from_be(&(*field_element).data) {
        Some(f) => f,
        None => return ZKVM_EFAIL,
    };
    let p = G1Projective::map_to_curve(&fp).clear_cofactor();
    encode_g1(p, &mut (*result).data);
    ZKVM_EOK
}

/// `zkvm_status zkvm_bls12_map_fp2_to_g2(...)` — Ethereum precompile 0x11
/// (EIP-2537). Same as above for Fp2 → G2.
#[no_mangle]
pub unsafe extern "C" fn zkvm_bls12_map_fp2_to_g2(
    field_element: *const Bls12381Fp2,
    result: *mut Bls12381G2Point,
) -> i32 {
    if field_element.is_null() || result.is_null() {
        return ZKVM_EFAIL;
    }
    let bytes = &(*field_element).data;
    // Fp2 layout per zkvm_accelerators.h: 96 bytes = c0 (48 BE) || c1 (48 BE).
    let c0 = match fp_from_be(bytes[0..48].try_into().unwrap()) {
        Some(f) => f,
        None => return ZKVM_EFAIL,
    };
    let c1 = match fp_from_be(bytes[48..96].try_into().unwrap()) {
        Some(f) => f,
        None => return ZKVM_EFAIL,
    };
    // A bls12_381 SWU bug sends u = 0 (and only u = 0) to infinity, so the
    // finite image EIP-2537 expects is hardcoded (execution-spec `fp_0` vector).
    if bool::from(c0.is_zero()) && bool::from(c1.is_zero()) {
        (*result).data = MAP_FP2_TO_G2_ZERO;
        return ZKVM_EOK;
    }
    let fp2 = bls12_381::fp2::Fp2 { c0, c1 };
    let p = G2Projective::map_to_curve(&fp2).clear_cofactor();
    encode_g2(p, &mut (*result).data);
    ZKVM_EOK
}

/// EIP-2537 image of `map_fp2_to_g2(0)` in the C ABI G2 encoding.
const MAP_FP2_TO_G2_ZERO: [u8; 192] = [
    0x01, 0x83, 0x20, 0x89, 0x6e, 0xc9, 0xee, 0xf9, 0xd5, 0xe6, 0x19, 0x84, //
    0x8d, 0xc2, 0x9c, 0xe2, 0x66, 0xf4, 0x13, 0xd0, 0x2d, 0xd3, 0x1d, 0x9b, //
    0x9d, 0x44, 0xec, 0x0c, 0x79, 0xcd, 0x61, 0xf1, 0x8b, 0x07, 0x5d, 0xdb, //
    0xa6, 0xd7, 0xbd, 0x20, 0xb7, 0xff, 0x27, 0xa4, 0xb3, 0x24, 0xbf, 0xce, //
    0x0a, 0x67, 0xd1, 0x21, 0x18, 0xb5, 0xa3, 0x5b, 0xb0, 0x2d, 0x2e, 0x86, //
    0xb3, 0xeb, 0xfa, 0x7e, 0x23, 0x41, 0x0d, 0xb9, 0x3d, 0xe3, 0x9f, 0xb0, //
    0x6d, 0x70, 0x25, 0xfa, 0x95, 0xe9, 0x6f, 0xfa, 0x42, 0x8a, 0x7a, 0x27, //
    0xc3, 0xae, 0x4d, 0xd4, 0xb4, 0x0b, 0xd2, 0x51, 0xac, 0x65, 0x88, 0x92, //
    0x02, 0x60, 0xe0, 0x36, 0x44, 0xd1, 0xa2, 0xc3, 0x21, 0x25, 0x6b, 0x32, //
    0x46, 0xba, 0xd2, 0xb8, 0x95, 0xca, 0xd1, 0x38, 0x90, 0xcb, 0xe6, 0xf8, //
    0x5d, 0xf5, 0x51, 0x06, 0xa0, 0xd3, 0x34, 0x60, 0x4f, 0xb1, 0x43, 0xc7, //
    0xa0, 0x42, 0xd8, 0x78, 0x00, 0x62, 0x71, 0x86, 0x5b, 0xc3, 0x59, 0x41, //
    0x04, 0xc6, 0x97, 0x77, 0xa4, 0x3f, 0x0b, 0xda, 0x07, 0x67, 0x9d, 0x58, //
    0x05, 0xe6, 0x3f, 0x18, 0xcf, 0x4e, 0x0e, 0x7c, 0x61, 0x12, 0xac, 0x7f, //
    0x70, 0x26, 0x6d, 0x19, 0x9b, 0x4f, 0x76, 0xae, 0x27, 0xc6, 0x26, 0x9a, //
    0x3c, 0xee, 0xbd, 0xae, 0x30, 0x80, 0x6e, 0x9a, 0x76, 0xaa, 0xdf, 0x5c, //
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precompile::types::{Bls12381Scalar, ZkvmBytes192, ZkvmBytes32, ZkvmBytes96};
    use bls12_381::fp::Fp;
    use bls12_381::fp2::Fp2;

    fn fp_small(v: u8) -> Fp {
        let mut b = [0u8; 48];
        b[47] = v;
        Fp::from_bytes(&b).unwrap()
    }

    /// Find an on-curve G1 point outside the q-order subgroup by walking
    /// small x-coordinates until y² = x³ + 4 has a root and the full
    /// (subgroup-checking) decode rejects the point. The cofactor is
    /// ~2^125, so the first on-curve candidate is essentially guaranteed
    /// to be outside the subgroup — but we check rather than assume.
    fn non_subgroup_g1() -> [u8; 96] {
        let four = fp_small(4);
        for i in 1..=u8::MAX {
            let x = fp_small(i);
            let y = match (x * x * x + four).sqrt().into_option() {
                Some(y) => y,
                None => continue,
            };
            let mut bytes = [0u8; 96];
            bytes[0..48].copy_from_slice(&x.to_bytes());
            bytes[48..96].copy_from_slice(&y.to_bytes());
            if G1Affine::from_uncompressed(&bytes).into_option().is_none() {
                return bytes;
            }
        }
        unreachable!("no on-curve non-subgroup G1 point among small x")
    }

    /// G2 analog: y² = x³ + 4(u + 1), encoded per EIP-2537
    /// (x.c0 || x.c1 || y.c0 || y.c1, each 48 BE bytes).
    fn non_subgroup_g2() -> [u8; 192] {
        let b = Fp2 { c0: fp_small(4), c1: fp_small(4) };
        for i in 1..=u8::MAX {
            let x = Fp2 { c0: fp_small(i), c1: Fp::zero() };
            let y = match (x * x * x + b).sqrt().into_option() {
                Some(y) => y,
                None => continue,
            };
            let mut bytes = [0u8; 192];
            bytes[0..48].copy_from_slice(&x.c0.to_bytes());
            bytes[48..96].copy_from_slice(&x.c1.to_bytes());
            bytes[96..144].copy_from_slice(&y.c0.to_bytes());
            bytes[144..192].copy_from_slice(&y.c1.to_bytes());
            if G2Affine::from_uncompressed(&g2_from_abi(&bytes)).into_option().is_none() {
                return bytes;
            }
        }
        unreachable!("no on-curve non-subgroup G2 point among small x")
    }

    const SCALAR_ONE: Bls12381Scalar = {
        let mut data = [0u8; 32];
        data[31] = 1;
        ZkvmBytes32 { data }
    };

    /// EIP-2537 G1ADD takes any on-curve point — no subgroup check.
    #[test]
    fn g1_add_accepts_non_subgroup_point() {
        let bytes = non_subgroup_g1();
        let p = ZkvmBytes96 { data: bytes };
        let mut out = ZkvmBytes96 { data: [0u8; 96] };
        let status = unsafe { zkvm_bls12_g1_add(&p, &p, &mut out) };
        assert_eq!(status, ZKVM_EOK);

        // The sum must be the curve double of the input.
        let a = G1Affine::from_uncompressed_unchecked(&bytes).unwrap();
        let expected = G1Affine::from(G1Projective::from(a).double()).to_uncompressed();
        assert_eq!(out.data, expected);
    }

    /// ...but G1MSM (0x0c) requires the subgroup check and must reject it.
    #[test]
    fn g1_msm_rejects_non_subgroup_point() {
        let pair = Bls12381G1MsmPair {
            point: ZkvmBytes96 { data: non_subgroup_g1() },
            scalar: SCALAR_ONE,
        };
        let mut out = ZkvmBytes96 { data: [0u8; 96] };
        let status = unsafe { zkvm_bls12_g1_msm(&pair, 1, &mut out) };
        assert_eq!(status, ZKVM_EFAIL);
    }

    /// The on-curve check must survive the relaxation: corrupting y off
    /// the curve is still rejected by G1ADD.
    #[test]
    fn g1_add_rejects_off_curve_point() {
        let mut bytes = non_subgroup_g1();
        // y += 1: leaves the curve unless y = -1/2, which sqrt never returns
        // for these inputs (checked by the decode assertion below).
        let y = Fp::from_bytes(bytes[48..96].try_into().unwrap()).unwrap();
        bytes[48..96].copy_from_slice(&(y + Fp::one()).to_bytes());
        assert!(decode_g1_on_curve(&bytes).is_none());

        let p = ZkvmBytes96 { data: bytes };
        let q = ZkvmBytes96 { data: non_subgroup_g1() };
        let mut out = ZkvmBytes96 { data: [0u8; 96] };
        let status = unsafe { zkvm_bls12_g1_add(&p, &q, &mut out) };
        assert_eq!(status, ZKVM_EFAIL);
    }

    /// Adding the point at infinity (all zeros) to a non-subgroup point
    /// returns the point unchanged.
    #[test]
    fn g1_add_non_subgroup_plus_infinity() {
        let bytes = non_subgroup_g1();
        let p = ZkvmBytes96 { data: bytes };
        let i = ZkvmBytes96 { data: [0u8; 96] };
        let mut out = ZkvmBytes96 { data: [0u8; 96] };
        let status = unsafe { zkvm_bls12_g1_add(&p, &i, &mut out) };
        assert_eq!(status, ZKVM_EOK);
        assert_eq!(out.data, bytes);
    }

    /// The crate's `0x40` infinity flag is non-canonical (>= p) and must be rejected.
    #[test]
    fn g1_add_rejects_infinity_flag_encoding() {
        let mut flagged = [0u8; 96];
        flagged[0] = 0x40;
        let p = ZkvmBytes96 { data: flagged };
        let g = ZkvmBytes96 { data: non_subgroup_g1() };
        let mut out = ZkvmBytes96 { data: [0u8; 96] };
        let status = unsafe { zkvm_bls12_g1_add(&p, &g, &mut out) };
        assert_eq!(status, ZKVM_EFAIL);
    }

    /// `map_fp2_to_g2(0)` maps to a fixed finite point, not infinity.
    #[test]
    fn map_fp2_to_g2_zero_is_finite() {
        let input = Bls12381Fp2 { data: [0u8; 96] };
        let mut out = ZkvmBytes192 { data: [0u8; 192] };
        let status = unsafe { zkvm_bls12_map_fp2_to_g2(&input, &mut out) };
        assert_eq!(status, ZKVM_EOK);
        assert_ne!(out.data, [0u8; 192]);
        assert!(decode_g2(&out.data).is_some());
    }

    /// EIP-2537 G2ADD takes any on-curve point — no subgroup check.
    #[test]
    fn g2_add_accepts_non_subgroup_point() {
        let bytes = non_subgroup_g2();
        let p = ZkvmBytes192 { data: bytes };
        let mut out = ZkvmBytes192 { data: [0u8; 192] };
        let status = unsafe { zkvm_bls12_g2_add(&p, &p, &mut out) };
        assert_eq!(status, ZKVM_EOK);

        let a = G2Affine::from_uncompressed_unchecked(&g2_from_abi(&bytes)).unwrap();
        let expected = g2_to_abi(G2Affine::from(G2Projective::from(a).double()).to_uncompressed());
        assert_eq!(out.data, expected);
    }

    /// ...but G2MSM (0x0e) requires the subgroup check and must reject it.
    #[test]
    fn g2_msm_rejects_non_subgroup_point() {
        let pair = Bls12381G2MsmPair {
            point: ZkvmBytes192 { data: non_subgroup_g2() },
            scalar: SCALAR_ONE,
        };
        let mut out = ZkvmBytes192 { data: [0u8; 192] };
        let status = unsafe { zkvm_bls12_g2_msm(&pair, 1, &mut out) };
        assert_eq!(status, ZKVM_EFAIL);
    }
}
