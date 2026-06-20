//! secp256r1 (P-256) verify — Ethereum precompile 0x100 (EIP-7212).

use crate::precompile::types::{Secp256r1Hash, Secp256r1Pubkey, Secp256r1Signature};
use crate::status::{ZKVM_EFAIL, ZKVM_EOK};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};

/// `zkvm_status zkvm_secp256r1_verify(...)`.
///
/// Pure-software ECDSA verify via the patched `p256` crate. At
/// `target_os = "zkvm"` the inner scalar multiplication and decompression
/// route through SP1's `SECP256R1_ADD`, `SECP256R1_DOUBLE`, and
/// `SECP256R1_DECOMPRESS` precompiles.
///
/// Pubkey layout matches `zkvm_secp256k1_verify`: raw 64-byte
/// uncompressed `x || y`; we prepend the SEC1 `0x04` tag before parsing.
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
