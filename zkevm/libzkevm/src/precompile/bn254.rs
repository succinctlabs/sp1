//! BN254 precompiles — Ethereum 0x06, 0x07, 0x08 (EIP-196 / EIP-197).

use crate::ecall;
use crate::precompile::types::{Bn254G1Point, Bn254PairingPair, Bn254Scalar};
use crate::status::ZKVM_EFAIL;

/// `zkvm_status zkvm_bn254_g1_add(p1, p2, result)`.
///
/// SP1 path: direct dispatch to `BN254_ADD` (0x00_01_01_0E).
#[no_mangle]
pub unsafe extern "C" fn zkvm_bn254_g1_add(
    p1: *const Bn254G1Point,
    p2: *const Bn254G1Point,
    result: *mut Bn254G1Point,
) -> i32 {
    if p1.is_null() || p2.is_null() || result.is_null() {
        return ZKVM_EFAIL;
    }
    // TODO: implementation. SP1's `BN254_ADD` operates in place on a0 with
    // a1 as the addend, so the wrapper needs to memcpy(p1 -> result) first.
    ecall::ecall3(ecall::placeholder::TODO_BN254_G1_ADD, p1 as usize, p2 as usize, result as usize);
    ZKVM_EFAIL
}

/// `zkvm_status zkvm_bn254_g1_mul(point, scalar, result)`.
///
/// SP1 path: windowed scalar mul on top of `BN254_ADD` + `BN254_DOUBLE`.
#[no_mangle]
pub unsafe extern "C" fn zkvm_bn254_g1_mul(
    point: *const Bn254G1Point,
    scalar: *const Bn254Scalar,
    result: *mut Bn254G1Point,
) -> i32 {
    if point.is_null() || scalar.is_null() || result.is_null() {
        return ZKVM_EFAIL;
    }
    // TODO: implementation
    ecall::ecall3(
        ecall::placeholder::TODO_BN254_G1_MUL,
        point as usize,
        scalar as usize,
        result as usize,
    );
    ZKVM_EFAIL
}

/// `zkvm_status zkvm_bn254_pairing(pairs, num_pairs, verified)`.
///
/// SP1 path: software Miller loop + final exponentiation over
/// `BN254_FP{,2}_{ADD,SUB,MUL}` precompiles.
#[no_mangle]
pub unsafe extern "C" fn zkvm_bn254_pairing(
    pairs: *const Bn254PairingPair,
    num_pairs: usize,
    verified: *mut bool,
) -> i32 {
    if (pairs.is_null() && num_pairs != 0) || verified.is_null() {
        return ZKVM_EFAIL;
    }
    // TODO: implementation
    ecall::ecall3(
        ecall::placeholder::TODO_BN254_PAIRING,
        pairs as usize,
        num_pairs,
        verified as usize,
    );
    ZKVM_EFAIL
}
