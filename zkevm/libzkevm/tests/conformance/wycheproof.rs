//! Full Wycheproof ECDSA suites against `zkvm_secp256k1_verify` and
//! `zkvm_secp256r1_verify`.
//!
//! The ABI takes a prehash + raw 64-byte `r || s`, so the glue here
//! hashes the message (via `zkvm_sha256`) and parses the vector's DER
//! signature strictly — Wycheproof's BER-laxity cases are `result:
//! "invalid"` and must fail somewhere, parser or verifier.

use crate::EOK;
use serde::Deserialize;
use std::path::PathBuf;
use zkevm::precompile::secp256k1::zkvm_secp256k1_verify;
use zkevm::precompile::secp256r1::zkvm_secp256r1_verify;
use zkevm::precompile::types::{ZkvmBytes32, ZkvmBytes64};

#[derive(Deserialize)]
struct File {
    #[serde(rename = "testGroups")]
    test_groups: Vec<Group>,
}

#[derive(Deserialize)]
struct Group {
    #[serde(rename = "publicKey")]
    public_key: Key,
    tests: Vec<Case>,
}

#[derive(Deserialize)]
struct Key {
    uncompressed: String,
}

#[derive(Deserialize)]
struct Case {
    #[serde(rename = "tcId")]
    tc_id: u32,
    comment: String,
    msg: String,
    sig: String,
    result: String,
}

fn load(name: &str) -> File {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/wycheproof")
        .join(format!("{name}.json"));
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = ZkvmBytes32 { data: [0u8; 32] };
    let status =
        unsafe { zkevm::precompile::hash::zkvm_sha256(data.as_ptr(), data.len(), &mut out) };
    assert_eq!(status, EOK);
    out.data
}

/// Strict-DER `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`
/// → 64-byte left-padded big-endian `r || s`. Any deviation (BER long
/// form, non-minimal integers, trailing bytes, oversized values) → None.
fn parse_der_signature(der: &[u8]) -> Option<[u8; 64]> {
    fn parse_integer<'a>(rest: &'a [u8], out: &mut [u8]) -> Option<&'a [u8]> {
        let [0x02, len, body @ ..] = rest else { return None };
        let len = *len as usize;
        // Short-form length only (valid r/s never need long form), and
        // a non-empty, non-negative, minimally-encoded integer.
        if len == 0 || len >= 0x80 || body.len() < len {
            return None;
        }
        let (value, rest) = body.split_at(len);
        if value[0] & 0x80 != 0 {
            return None; // negative
        }
        if len > 1 && value[0] == 0 && value[1] & 0x80 == 0 {
            return None; // non-minimal leading zero
        }
        let value = if value[0] == 0 { &value[1..] } else { value };
        if value.len() > 32 {
            return None; // exceeds field width
        }
        out[32 - value.len()..].copy_from_slice(value);
        Some(rest)
    }

    let [0x30, len, body @ ..] = der else { return None };
    if *len as usize != body.len() || *len >= 0x80 {
        return None;
    }
    let mut sig = [0u8; 64];
    let rest = parse_integer(body, &mut sig[0..32])?;
    let rest = parse_integer(rest, &mut sig[32..64])?;
    rest.is_empty().then_some(sig)
}

type VerifyFn = unsafe extern "C" fn(
    *const ZkvmBytes32,
    *const ZkvmBytes64,
    *const ZkvmBytes64,
    *mut bool,
) -> i32;

fn run_suite(file: &str, verify: VerifyFn) {
    let suite = load(file);
    let mut total = 0usize;
    for group in &suite.test_groups {
        let uncompressed = hex::decode(&group.public_key.uncompressed).unwrap();
        // Raw 64-byte x || y per the ABI: strip the SEC1 0x04 tag.
        assert_eq!(uncompressed.len(), 65, "{file}: unexpected pubkey form");
        assert_eq!(uncompressed[0], 0x04, "{file}: unexpected pubkey form");
        let pubkey = ZkvmBytes64 { data: uncompressed[1..].try_into().unwrap() };

        for case in &group.tests {
            total += 1;
            let verified = match parse_der_signature(&hex::decode(&case.sig).unwrap()) {
                None => false,
                Some(sig) => {
                    let msg = ZkvmBytes32 { data: sha256(&hex::decode(&case.msg).unwrap()) };
                    let sig = ZkvmBytes64 { data: sig };
                    let mut verified = false;
                    let status = unsafe { verify(&msg, &sig, &pubkey, &mut verified) };
                    assert_eq!(status, EOK, "{file} tc{}: ABI misuse reported", case.tc_id);
                    verified
                }
            };
            match case.result.as_str() {
                "valid" => {
                    assert!(
                        verified,
                        "{file} tc{} ({}): valid sig rejected",
                        case.tc_id, case.comment
                    )
                }
                "invalid" => {
                    assert!(
                        !verified,
                        "{file} tc{} ({}): invalid sig accepted",
                        case.tc_id, case.comment
                    )
                }
                "acceptable" => {} // implementation-defined either way
                other => panic!("{file} tc{}: unknown result {other:?}", case.tc_id),
            }
        }
    }
    // Guard against silently running a truncated download.
    assert!(total > 300, "{file}: only {total} cases — suite incomplete?");
}

#[test]
fn wycheproof_ecdsa_secp256k1() {
    run_suite("ecdsa_secp256k1_sha256_test", zkvm_secp256k1_verify);
}

#[test]
fn wycheproof_ecdsa_secp256r1() {
    run_suite("ecdsa_secp256r1_sha256_test", zkvm_secp256r1_verify);
}
