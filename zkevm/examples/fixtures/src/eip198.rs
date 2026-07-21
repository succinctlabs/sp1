//! EIP-198 (modexp / precompile 0x05) golden vectors.
//!
//! Each vector encodes (base, exp, modulus, expected) as separate
//! big-endian byte strings. The `expected` field has length equal to
//! `modulus.len()`; per EIP-198, the output is zero-padded on the left
//! to `mod_len` bytes. `modulus = 0` yields `mod_len` zero bytes.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Raw {
    name: String,
    base: String,
    exp: String,
    modulus: String,
    expected: String,
}

/// One parsed EIP-198 modexp test case.
#[derive(Debug)]
pub struct Vector {
    pub name: String,
    pub base: Vec<u8>,
    pub exp: Vec<u8>,
    pub modulus: Vec<u8>,
    pub expected: Vec<u8>,
}

const JSON: &str = include_str!("../data/eip198/modexp.json");

fn decode_hex(s: &str) -> Vec<u8> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    if trimmed.is_empty() {
        return Vec::new();
    }
    hex::decode(trimmed).expect("eip-198 fixture hex")
}

/// Iterate over all bundled EIP-198 modexp cases.
pub fn vectors() -> impl Iterator<Item = Vector> {
    let raw: Vec<Raw> = serde_json::from_str(JSON).expect("eip-198 fixture parses");
    raw.into_iter().map(|r| Vector {
        name: r.name,
        base: decode_hex(&r.base),
        exp: decode_hex(&r.exp),
        modulus: decode_hex(&r.modulus),
        expected: decode_hex(&r.expected),
    })
}
