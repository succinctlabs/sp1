//! secp256k1: signature verification (precompile-less helper) and ECRECOVER (0x01).

use crate::ecall;
use crate::precompile::types::{Secp256k1Hash, Secp256k1Pubkey, Secp256k1Signature};
use crate::status::ZKVM_EFAIL;

/// `zkvm_status zkvm_secp256k1_verify(...)` — non-precompile helper.
///
/// SP1 path: pure software ECDSA verify on top of `SECP256K1_ADD`,
/// `SECP256K1_DOUBLE`, and `SECP256K1_DECOMPRESS`. No new syscall needed.
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
    // TODO: implementation
    ecall::ecall4(
        ecall::placeholder::TODO_SECP256K1_VERIFY,
        msg as usize,
        sig as usize,
        pubkey as usize,
        verified as usize,
    );
    ZKVM_EFAIL
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
