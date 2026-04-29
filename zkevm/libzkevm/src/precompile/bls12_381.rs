//! BLS12-381 precompiles — Ethereum 0x0b..0x11 (EIP-2537).

use crate::ecall;
use crate::precompile::types::{
    Bls12381Fp, Bls12381Fp2, Bls12381G1MsmPair, Bls12381G1Point, Bls12381G2MsmPair,
    Bls12381G2Point, Bls12381PairingPair,
};
use crate::status::ZKVM_EFAIL;

#[no_mangle]
pub unsafe extern "C" fn zkvm_bls12_g1_add(
    p1: *const Bls12381G1Point,
    p2: *const Bls12381G1Point,
    result: *mut Bls12381G1Point,
) -> i32 {
    if p1.is_null() || p2.is_null() || result.is_null() {
        return ZKVM_EFAIL;
    }
    // TODO: implementation — dispatch to `BLS12381_ADD` after copying p1 -> result.
    ecall::ecall3(ecall::placeholder::TODO_BLS12_G1_ADD, p1 as usize, p2 as usize, result as usize);
    ZKVM_EFAIL
}

#[no_mangle]
pub unsafe extern "C" fn zkvm_bls12_g1_msm(
    pairs: *const Bls12381G1MsmPair,
    num_pairs: usize,
    result: *mut Bls12381G1Point,
) -> i32 {
    if (pairs.is_null() && num_pairs != 0) || result.is_null() {
        return ZKVM_EFAIL;
    }
    // TODO: implementation — Pippenger over `BLS12381_ADD`/`BLS12381_DOUBLE`.
    ecall::ecall3(
        ecall::placeholder::TODO_BLS12_G1_MSM,
        pairs as usize,
        num_pairs,
        result as usize,
    );
    ZKVM_EFAIL
}

#[no_mangle]
pub unsafe extern "C" fn zkvm_bls12_g2_add(
    p1: *const Bls12381G2Point,
    p2: *const Bls12381G2Point,
    result: *mut Bls12381G2Point,
) -> i32 {
    if p1.is_null() || p2.is_null() || result.is_null() {
        return ZKVM_EFAIL;
    }
    // TODO: implementation — software G2 add over BLS12381_FP2_* ops.
    ecall::ecall3(ecall::placeholder::TODO_BLS12_G2_ADD, p1 as usize, p2 as usize, result as usize);
    ZKVM_EFAIL
}

#[no_mangle]
pub unsafe extern "C" fn zkvm_bls12_g2_msm(
    pairs: *const Bls12381G2MsmPair,
    num_pairs: usize,
    result: *mut Bls12381G2Point,
) -> i32 {
    if (pairs.is_null() && num_pairs != 0) || result.is_null() {
        return ZKVM_EFAIL;
    }
    // TODO: implementation
    ecall::ecall3(
        ecall::placeholder::TODO_BLS12_G2_MSM,
        pairs as usize,
        num_pairs,
        result as usize,
    );
    ZKVM_EFAIL
}

#[no_mangle]
pub unsafe extern "C" fn zkvm_bls12_pairing(
    pairs: *const Bls12381PairingPair,
    num_pairs: usize,
    verified: *mut bool,
) -> i32 {
    if (pairs.is_null() && num_pairs != 0) || verified.is_null() {
        return ZKVM_EFAIL;
    }
    // TODO: implementation
    ecall::ecall3(
        ecall::placeholder::TODO_BLS12_PAIRING,
        pairs as usize,
        num_pairs,
        verified as usize,
    );
    ZKVM_EFAIL
}

#[no_mangle]
pub unsafe extern "C" fn zkvm_bls12_map_fp_to_g1(
    field_element: *const Bls12381Fp,
    result: *mut Bls12381G1Point,
) -> i32 {
    if field_element.is_null() || result.is_null() {
        return ZKVM_EFAIL;
    }
    // TODO: implementation — SSWU map; SP1 has no precompile for this yet.
    ecall::ecall2(
        ecall::placeholder::TODO_BLS12_MAP_FP_TO_G1,
        field_element as usize,
        result as usize,
    );
    ZKVM_EFAIL
}

#[no_mangle]
pub unsafe extern "C" fn zkvm_bls12_map_fp2_to_g2(
    field_element: *const Bls12381Fp2,
    result: *mut Bls12381G2Point,
) -> i32 {
    if field_element.is_null() || result.is_null() {
        return ZKVM_EFAIL;
    }
    // TODO: implementation
    ecall::ecall2(
        ecall::placeholder::TODO_BLS12_MAP_FP2_TO_G2,
        field_element as usize,
        result as usize,
    );
    ZKVM_EFAIL
}
