//! Full Wycheproof ECDSA suites against `zkvm_secp256k1_verify` and
//! `zkvm_secp256r1_verify`.
//!
//! The ABI takes a prehash + raw 64-byte `r || s`, so the glue here
//! hashes the message (via `zkvm_sha256`) and parses the vector's DER
//! signature strictly — Wycheproof's BER-laxity cases are `result:
//! "invalid"` and must fail somewhere, parser or verifier.

use crate::support::{load_wycheproof, parse_der_signature};
use crate::EOK;
use zkevm::precompile::secp256k1::zkvm_secp256k1_verify;
use zkevm::precompile::secp256r1::zkvm_secp256r1_verify;
use zkevm::precompile::types::{ZkvmBytes32, ZkvmBytes64};

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = ZkvmBytes32 { data: [0u8; 32] };
    let status =
        unsafe { zkevm::precompile::hash::zkvm_sha256(data.as_ptr(), data.len(), &mut out) };
    assert_eq!(status, EOK);
    out.data
}

type VerifyFn = unsafe extern "C" fn(
    *const ZkvmBytes32,
    *const ZkvmBytes64,
    *const ZkvmBytes64,
    *mut bool,
) -> i32;

fn run_suite(file: &str, verify: VerifyFn) {
    let suite = load_wycheproof(file);
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
