//! ECDSA test vectors from Google's Wycheproof project
//! (`ecdsa_secp256k1_sha256_p1363_test.json`).
//!
//! Wycheproof groups vectors by signing key. Each test inside a group
//! gives a message + signature + expected outcome (`valid` / `invalid`)
//! and a free-form `comment` plus `flags` describing which edge case is
//! being exercised — signature malleability, modular-inverse traps,
//! integer overflows, modified-r-or-s, etc. (See
//! <https://github.com/google/wycheproof>.)
//!
//! Our `zkvm_secp256k1_verify` API takes a 32-byte message *prehash*
//! (SHA-256 of the Wycheproof `msg`), a 64-byte `r || s` signature, and
//! a 64-byte uncompressed `x || y` pubkey (no SEC1 `0x04` tag), so we
//! re-format each vector accordingly.

use serde::Deserialize;
use sha2::{Digest, Sha256};

const RAW_JSON: &str = include_str!("../data/wycheproof/ecdsa_secp256k1_sha256_p1363_test.json");

#[derive(Debug, Deserialize)]
struct TopLevel {
    #[serde(rename = "testGroups")]
    test_groups: Vec<RawGroup>,
}

#[derive(Debug, Deserialize)]
struct RawGroup {
    #[serde(rename = "publicKey")]
    public_key: RawPubKey,
    tests: Vec<RawTest>,
}

#[derive(Debug, Deserialize)]
struct RawPubKey {
    /// Uncompressed SEC1: `04 || x || y` (130 hex chars / 65 bytes).
    uncompressed: String,
}

#[derive(Debug, Deserialize)]
struct RawTest {
    #[serde(rename = "tcId")]
    tc_id: u32,
    comment: String,
    msg: String,
    sig: String,
    result: String,
    #[serde(default)]
    flags: Vec<String>,
}

/// One Wycheproof ECDSA test case adapted to our C ABI's expectations.
#[derive(Debug)]
pub struct Vector {
    pub tc_id: u32,
    pub comment: String,
    pub flags: Vec<String>,
    pub msg_prehash: [u8; 32],
    pub sig: [u8; 64],
    pub pubkey_xy: [u8; 64],
    pub expected_valid: bool,
}

/// Iterate over every Wycheproof case that fits our fixed-width API
/// (signature is exactly 64 bytes, uncompressed pubkey is 65 bytes
/// starting with `0x04`). Cases that don't fit are skipped — those
/// test wire-format validation that our `zkvm_secp256k1_signature` /
/// `zkvm_secp256k1_pubkey` types enforce structurally before the call
/// reaches libzkevm.
pub fn vectors() -> impl Iterator<Item = Vector> {
    let top: TopLevel = serde_json::from_str(RAW_JSON).expect("wycheproof json parses");
    top.test_groups.into_iter().flat_map(|g| {
        let pk_hex = g.public_key.uncompressed;
        let pk_bytes = hex::decode(&pk_hex).unwrap_or_default();
        // Only handle the standard uncompressed form (65 bytes: 0x04 || x || y).
        let pk_xy = if pk_bytes.len() == 65 && pk_bytes[0] == 0x04 {
            let mut xy = [0u8; 64];
            xy.copy_from_slice(&pk_bytes[1..]);
            Some(xy)
        } else {
            None
        };
        g.tests.into_iter().filter_map(move |t| {
            let xy = pk_xy?;
            let msg = hex::decode(&t.msg).ok()?;
            let sig_bytes = hex::decode(&t.sig).ok()?;
            // P1363 sigs have unpadded variable-length; only the 64-byte
            // canonical form is reachable through our fixed-width API.
            if sig_bytes.len() != 64 {
                return None;
            }
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&sig_bytes);

            let prehash: [u8; 32] = Sha256::digest(&msg).into();
            let expected_valid = match t.result.as_str() {
                "valid" => true,
                "invalid" => false,
                // Wycheproof also has an "acceptable" tier for cases that
                // are technically not malformed but that callers may want
                // to reject — none in this file at v1, but be defensive.
                _ => return None,
            };
            Some(Vector {
                tc_id: t.tc_id,
                comment: t.comment,
                flags: t.flags,
                msg_prehash: prehash,
                sig,
                pubkey_xy: xy,
                expected_valid,
            })
        })
    })
}
