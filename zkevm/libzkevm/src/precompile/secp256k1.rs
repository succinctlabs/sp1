//! secp256k1: signature verification (precompile-less helper) and ECRECOVER (0x01).

use crate::ecall;
use crate::precompile::types::{Secp256k1Hash, Secp256k1Pubkey, Secp256k1Signature};
use crate::status::{ZKVM_EFAIL, ZKVM_EOK};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};

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
/// SP1 path: ask the host for a recovered pubkey via `FD_ECRECOVER_HOOK`,
/// then verify it in-circuit using `SECP256K1_ADD`/`SECP256K1_DOUBLE`.
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
    // TODO: implementation
    ecall::ecall4(
        ecall::placeholder::TODO_ECRECOVER,
        msg as usize,
        sig as usize,
        recid as usize,
        output as usize,
    );
    ZKVM_EFAIL
}
