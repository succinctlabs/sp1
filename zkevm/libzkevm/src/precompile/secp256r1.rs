//! secp256r1 (P-256) verify — Ethereum precompile 0x100 (EIP-7212).

use crate::ecall;
use crate::precompile::types::{Secp256r1Hash, Secp256r1Pubkey, Secp256r1Signature};
use crate::status::ZKVM_EFAIL;

/// `zkvm_status zkvm_secp256r1_verify(...)`.
///
/// SP1 path: software ECDSA verify on top of `SECP256R1_ADD`/`SECP256R1_DOUBLE`/
/// `SECP256R1_DECOMPRESS`.
#[no_mangle]
pub unsafe extern "C" fn zkvm_secp256r1_verify(
    msg: *const Secp256r1Hash,
    sig: *const Secp256r1Signature,
    pubkey: *const Secp256r1Pubkey,
    verified: *mut bool,
) -> i32 {
    if msg.is_null() || sig.is_null() || pubkey.is_null() || verified.is_null() {
        return ZKVM_EFAIL;
    }
    // TODO: implementation
    ecall::ecall4(
        ecall::placeholder::TODO_SECP256R1_VERIFY,
        msg as usize,
        sig as usize,
        pubkey as usize,
        verified as usize,
    );
    ZKVM_EFAIL
}
