//! Hash precompile stubs: Keccak-256, SHA-256, RIPEMD-160.

use crate::ecall;
use crate::precompile::types::{Keccak256Hash, Ripemd160Hash, Sha256Hash};
use crate::status::{ZKVM_EFAIL, ZKVM_EOK};

/// `zkvm_status zkvm_keccak256(const uint8_t* data, size_t len, zkvm_keccak256_hash* output)`.
///
/// SP1 path: loop over the `KECCAK_PERMUTE` precompile applying the standard
/// Keccak-f sponge with rate=1088, capacity=512, and the Keccak (not SHA-3)
/// padding rule (0x01 / 0x80).
#[no_mangle]
pub unsafe extern "C" fn zkvm_keccak256(
    data: *const u8,
    len: usize,
    output: *mut Keccak256Hash,
) -> i32 {
    if data.is_null() && len != 0 {
        return ZKVM_EFAIL;
    }
    if output.is_null() {
        return ZKVM_EFAIL;
    }
    // TODO: implementation — sponge over `ecall::sp1::KECCAK_PERMUTE`.
    ecall::ecall3(ecall::placeholder::TODO_KECCAK256, data as usize, len, output as usize);
    let _ = ZKVM_EOK;
    ZKVM_EFAIL
}

/// `zkvm_status zkvm_sha256(const uint8_t* data, size_t len, zkvm_sha256_hash* output)`.
///
/// SP1 path: loop over `SHA_EXTEND` + `SHA_COMPRESS` with FIPS-180 padding.
#[no_mangle]
pub unsafe extern "C" fn zkvm_sha256(data: *const u8, len: usize, output: *mut Sha256Hash) -> i32 {
    if data.is_null() && len != 0 {
        return ZKVM_EFAIL;
    }
    if output.is_null() {
        return ZKVM_EFAIL;
    }
    // TODO: implementation
    ecall::ecall3(ecall::placeholder::TODO_SHA256, data as usize, len, output as usize);
    ZKVM_EFAIL
}

/// `zkvm_status zkvm_ripemd160(const uint8_t* data, size_t len, zkvm_ripemd160_hash* output)`.
///
/// SP1 path: no precompile; software impl is acceptable since RIPEMD-160 is
/// not on the L1 STF hot path. Output is 20 hash bytes followed by 12 zero
/// bytes (header docs).
#[no_mangle]
pub unsafe extern "C" fn zkvm_ripemd160(
    data: *const u8,
    len: usize,
    output: *mut Ripemd160Hash,
) -> i32 {
    if data.is_null() && len != 0 {
        return ZKVM_EFAIL;
    }
    if output.is_null() {
        return ZKVM_EFAIL;
    }
    // TODO: implementation (likely software, padded to 32 bytes).
    ecall::ecall3(ecall::placeholder::TODO_RIPEMD160, data as usize, len, output as usize);
    ZKVM_EFAIL
}
