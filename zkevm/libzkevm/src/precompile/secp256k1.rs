//! secp256k1: signature verification (precompile-less helper) and ECRECOVER (0x01).

use crate::precompile::types::{Secp256k1Hash, Secp256k1Pubkey, Secp256k1Signature};
use crate::status::{ZKVM_EFAIL, ZKVM_EOK};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

/// `zkvm_status zkvm_secp256k1_verify(...)` — non-precompile helper.
///
/// Pure-software ECDSA verify via the patched `k256` crate. At
/// `target_os = "zkvm"` the inner scalar multiplication and decompression
/// route through SP1's `SECP256K1_ADD`, `SECP256K1_DOUBLE`, and
/// `SECP256K1_DECOMPRESS` precompiles. No new SP1 syscall is required.
///
/// Pubkey layout per `zkvm_accelerators.h` is the raw 64-byte uncompressed
/// `x || y` (no SEC1 `0x04` tag); we prepend `0x04` before handing it to
/// `VerifyingKey::from_sec1_bytes`.
#[no_mangle]
pub unsafe extern "C" fn zkvm_secp256k1_verify(
    msg: *const Secp256k1Hash,
    sig: *const Secp256k1Signature,
    pubkey: *const Secp256k1Pubkey,
    verified: *mut bool,
) -> i32 {
    if msg.is_null() || sig.is_null() || pubkey.is_null() || verified.is_null() {
        return ZKVM_EFAIL;
    }

    let msg_bytes = &(*msg).data;
    let sig_bytes = &(*sig).data;
    let pk_bytes = &(*pubkey).data;

    let signature = match Signature::from_slice(sig_bytes) {
        Ok(s) => s,
        Err(_) => {
            *verified = false;
            return ZKVM_EOK;
        }
    };
    // Plain-ECDSA semantics: accept high-s signatures (matching the
    // p256 helper and Wycheproof's `valid` results). k256's
    // `verify_prehash` enforces bitcoin's low-s rule, so normalize
    // first; (r, n - s) verifies iff (r, s) does.
    let signature = signature.normalize_s().unwrap_or(signature);

    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(pk_bytes);
    let vk = match VerifyingKey::from_sec1_bytes(&sec1) {
        Ok(v) => v,
        Err(_) => {
            *verified = false;
            return ZKVM_EOK;
        }
    };

    *verified = vk.verify_prehash(msg_bytes, &signature).is_ok();
    ZKVM_EOK
}

/// `zkvm_status zkvm_secp256k1_ecrecover(...)` — Ethereum precompile 0x01.
///
/// Recovers the SEC1 uncompressed public key (without the leading `0x04`
/// tag) from a 32-byte message hash, a 64-byte `r || s` signature, and a
/// 1-byte recovery id. At `target_os = "zkvm"` the patched `k256` crate
/// fast-paths recovery through SP1's `FD_ECRECOVER_HOOK` and verifies
/// the recovered point with `SECP256K1_ADD`/`SECP256K1_DOUBLE`.
///
/// `recid` is the standard ECDSA recovery id (0..=3); higher values are
/// rejected. Output layout matches `zkvm_secp256k1_pubkey`: 64 bytes
/// uncompressed `x || y`.
#[no_mangle]
pub unsafe extern "C" fn zkvm_secp256k1_ecrecover(
    msg: *const Secp256k1Hash,
    sig: *const Secp256k1Signature,
    recid: u8,
    output: *mut Secp256k1Pubkey,
) -> i32 {
    if msg.is_null() || sig.is_null() || output.is_null() {
        return ZKVM_EFAIL;
    }

    let msg_bytes = &(*msg).data;
    let sig_bytes = &(*sig).data;

    let signature = match Signature::from_slice(sig_bytes) {
        Ok(s) => s,
        Err(_) => return ZKVM_EFAIL,
    };

    let recovery_id = match RecoveryId::try_from(recid) {
        Ok(r) => r,
        Err(_) => return ZKVM_EFAIL,
    };

    // Ethereum's ecrecover accepts high-s signatures (EIP-2's low-s rule
    // binds transaction signatures, not the precompile), but k256's
    // recovery enforces low-s. Normalize and flip the parity bit:
    // (r, n - s) with inverted y-parity recovers the same key.
    let (signature, recovery_id) = match signature.normalize_s() {
        Some(normalized) => {
            (normalized, RecoveryId::new(!recovery_id.is_y_odd(), recovery_id.is_x_reduced()))
        }
        None => (signature, recovery_id),
    };

    let vk = match VerifyingKey::recover_from_prehash(msg_bytes, &signature, recovery_id) {
        Ok(v) => v,
        Err(_) => return ZKVM_EFAIL,
    };

    let encoded = vk.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return ZKVM_EFAIL;
    }
    (*output).data.copy_from_slice(&bytes[1..]);
    ZKVM_EOK
}
