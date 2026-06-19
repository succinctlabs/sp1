//! EIP-196 (BN254 G1 add + scalar mul / precompiles 0x06, 0x07) golden vectors.
//!
//! Coordinates use the libzkevm C-ABI layout (not the EVM ABI): each G1
//! point is 64 bytes `x (32 BE) || y (32 BE)`, with `(0, 0)` denoting
//! the point at infinity. Scalars are 32 BE bytes.
//!
//! Reference values were generated with `py_ecc.bn128` for the BN254
//! generator `G = (1, 2)` and its small multiples.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct RawAdd {
    name: String,
    p1: String,
    p2: String,
    expected: String,
}

#[derive(Debug, Deserialize)]
struct RawMul {
    name: String,
    point: String,
    scalar: String,
    expected: String,
}

/// One parsed EIP-196 G1 add case.
#[derive(Debug)]
pub struct AddVector {
    pub name: String,
    pub p1: [u8; 64],
    pub p2: [u8; 64],
    pub expected: [u8; 64],
}

/// One parsed EIP-196 G1 scalar-mul case.
#[derive(Debug)]
pub struct MulVector {
    pub name: String,
    pub point: [u8; 64],
    pub scalar: [u8; 32],
    pub expected: [u8; 64],
}

const ADD_JSON: &str = include_str!("../data/eip196/g1_add.json");
const MUL_JSON: &str = include_str!("../data/eip196/g1_mul.json");

fn decode_fixed<const N: usize>(s: &str) -> [u8; N] {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(trimmed).expect("eip-196 fixture hex");
    bytes.try_into().expect("eip-196 fixture length")
}

/// Iterate over all bundled EIP-196 G1-add cases.
pub fn add_vectors() -> impl Iterator<Item = AddVector> {
    let raw: Vec<RawAdd> = serde_json::from_str(ADD_JSON).expect("eip-196 add fixture parses");
    raw.into_iter().map(|r| AddVector {
        name: r.name,
        p1: decode_fixed::<64>(&r.p1),
        p2: decode_fixed::<64>(&r.p2),
        expected: decode_fixed::<64>(&r.expected),
    })
}

/// Iterate over all bundled EIP-196 G1 scalar-mul cases.
pub fn mul_vectors() -> impl Iterator<Item = MulVector> {
    let raw: Vec<RawMul> = serde_json::from_str(MUL_JSON).expect("eip-196 mul fixture parses");
    raw.into_iter().map(|r| MulVector {
        name: r.name,
        point: decode_fixed::<64>(&r.point),
        scalar: decode_fixed::<32>(&r.scalar),
        expected: decode_fixed::<64>(&r.expected),
    })
}
