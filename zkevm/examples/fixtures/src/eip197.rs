//! EIP-197 (BN254 pairing / precompile 0x08) golden vectors.
//!
//! The `pairs` field is a concatenation of `(G1 64B || G2 128B)` pairs
//! in the libzkevm C-ABI layout. G1 = `x || y` BE; G2 follows the
//! EIP-197 coordinate ordering `x.a1 || x.a0 || y.a1 || y.a0` BE.
//! Empty input encodes "zero pairs", which must verify per EIP-197
//! (the empty product equals the identity in `Gt`).

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Raw {
    name: String,
    pairs: String,
    expected_verified: bool,
}

/// One parsed EIP-197 pairing-check case.
#[derive(Debug)]
pub struct Vector {
    pub name: String,
    /// Concatenated `(G1 || G2)` pairs; length is `num_pairs * 192`.
    pub pairs: Vec<u8>,
    pub expected_verified: bool,
}

impl Vector {
    pub fn num_pairs(&self) -> usize {
        self.pairs.len() / (64 + 128)
    }
}

const JSON: &str = include_str!("../data/eip197/pairing.json");

fn decode_hex(s: &str) -> Vec<u8> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    if trimmed.is_empty() {
        return Vec::new();
    }
    hex::decode(trimmed).expect("eip-197 fixture hex")
}

/// Iterate over all bundled EIP-197 pairing-check cases.
pub fn vectors() -> impl Iterator<Item = Vector> {
    let raw: Vec<Raw> = serde_json::from_str(JSON).expect("eip-197 fixture parses");
    raw.into_iter().map(|r| Vector {
        name: r.name,
        pairs: decode_hex(&r.pairs),
        expected_verified: r.expected_verified,
    })
}
