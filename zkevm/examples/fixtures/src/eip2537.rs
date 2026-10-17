//! EIP-2537 (BLS12-381 / precompiles 0x0b–0x11) golden vectors.
//!
//! Encoding follows libzkevm's C ABI (EIP-2537 with the 16-byte per-Fp
//! padding stripped):
//!
//! * G1 = 96 bytes (Fp x || Fp y), each Fp = 48 BE bytes.
//! * G2 = 192 bytes (Fp2 x || Fp2 y), each Fp2 = `c0 || c1` (96 BE).
//! * Point at infinity is all-zero bytes.
//! * Scalars are 32 BE bytes (reduced mod the BLS12-381 group order).
//!
//! Reference values generated with `py_ecc.bls12_381` for the canonical
//! generator and its small multiples.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct RawAdd {
    name: String,
    p1: String,
    p2: String,
    expected: String,
}

#[derive(Debug, Deserialize)]
struct RawMsm {
    name: String,
    pairs: String,
    expected: String,
}

#[derive(Debug, Deserialize)]
struct RawPairing {
    name: String,
    pairs: String,
    expected_verified: bool,
}

#[derive(Debug)]
pub struct G1AddVector {
    pub name: String,
    pub p1: [u8; 96],
    pub p2: [u8; 96],
    pub expected: [u8; 96],
}

#[derive(Debug)]
pub struct G2AddVector {
    pub name: String,
    pub p1: [u8; 192],
    pub p2: [u8; 192],
    pub expected: [u8; 192],
}

#[derive(Debug)]
pub struct G1MsmVector {
    pub name: String,
    /// Concatenated `(point 96 || scalar 32)` pairs.
    pub pairs: Vec<u8>,
    pub expected: [u8; 96],
}

#[derive(Debug)]
pub struct G2MsmVector {
    pub name: String,
    /// Concatenated `(point 192 || scalar 32)` pairs.
    pub pairs: Vec<u8>,
    pub expected: [u8; 192],
}

#[derive(Debug)]
pub struct PairingVector {
    pub name: String,
    /// Concatenated `(G1 96 || G2 192)` pairs.
    pub pairs: Vec<u8>,
    pub expected_verified: bool,
}

const G1_ADD_JSON: &str = include_str!("../data/eip2537/g1_add.json");
const G2_ADD_JSON: &str = include_str!("../data/eip2537/g2_add.json");
const G1_MSM_JSON: &str = include_str!("../data/eip2537/g1_msm.json");
const G2_MSM_JSON: &str = include_str!("../data/eip2537/g2_msm.json");
const PAIRING_JSON: &str = include_str!("../data/eip2537/pairing.json");

fn decode_hex(s: &str) -> Vec<u8> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    if trimmed.is_empty() {
        return Vec::new();
    }
    hex::decode(trimmed).expect("eip-2537 fixture hex")
}

fn decode_fixed<const N: usize>(s: &str) -> [u8; N] {
    decode_hex(s).try_into().expect("eip-2537 fixture length")
}

pub fn g1_add_vectors() -> impl Iterator<Item = G1AddVector> {
    let raw: Vec<RawAdd> = serde_json::from_str(G1_ADD_JSON).expect("eip-2537 g1_add fixture");
    raw.into_iter().map(|r| G1AddVector {
        name: r.name,
        p1: decode_fixed::<96>(&r.p1),
        p2: decode_fixed::<96>(&r.p2),
        expected: decode_fixed::<96>(&r.expected),
    })
}

pub fn g2_add_vectors() -> impl Iterator<Item = G2AddVector> {
    let raw: Vec<RawAdd> = serde_json::from_str(G2_ADD_JSON).expect("eip-2537 g2_add fixture");
    raw.into_iter().map(|r| G2AddVector {
        name: r.name,
        p1: decode_fixed::<192>(&r.p1),
        p2: decode_fixed::<192>(&r.p2),
        expected: decode_fixed::<192>(&r.expected),
    })
}

pub fn g1_msm_vectors() -> impl Iterator<Item = G1MsmVector> {
    let raw: Vec<RawMsm> = serde_json::from_str(G1_MSM_JSON).expect("eip-2537 g1_msm fixture");
    raw.into_iter().map(|r| G1MsmVector {
        name: r.name,
        pairs: decode_hex(&r.pairs),
        expected: decode_fixed::<96>(&r.expected),
    })
}

pub fn g2_msm_vectors() -> impl Iterator<Item = G2MsmVector> {
    let raw: Vec<RawMsm> = serde_json::from_str(G2_MSM_JSON).expect("eip-2537 g2_msm fixture");
    raw.into_iter().map(|r| G2MsmVector {
        name: r.name,
        pairs: decode_hex(&r.pairs),
        expected: decode_fixed::<192>(&r.expected),
    })
}

pub fn pairing_vectors() -> impl Iterator<Item = PairingVector> {
    let raw: Vec<RawPairing> =
        serde_json::from_str(PAIRING_JSON).expect("eip-2537 pairing fixture");
    raw.into_iter().map(|r| PairingVector {
        name: r.name,
        pairs: decode_hex(&r.pairs),
        expected_verified: r.expected_verified,
    })
}
