//! KZG point evaluation — Ethereum precompile 0x0a (EIP-4844).

use crate::ecall;
use crate::precompile::types::{KzgCommitment, KzgFieldElement, KzgProof};
use crate::status::ZKVM_EFAIL;

/// `zkvm_status zkvm_kzg_point_eval(commitment, z, y, proof, verified)`.
///
/// SP1 path: software KZG verifier on top of BLS12-381 precompiles. The
/// trusted-setup G2 generators are constants compiled into the guest.
#[no_mangle]
pub unsafe extern "C" fn zkvm_kzg_point_eval(
    commitment: *const KzgCommitment,
    z: *const KzgFieldElement,
    y: *const KzgFieldElement,
    proof: *const KzgProof,
    verified: *mut bool,
) -> i32 {
    if commitment.is_null() || z.is_null() || y.is_null() || proof.is_null() || verified.is_null() {
        return ZKVM_EFAIL;
    }
    // TODO: implementation. 5 args > 4 — collapse into a struct via a0 once
    // wired, or split into a setup+verify pair.
    let _ = (commitment, z, y, proof, verified);
    ecall::ecall0(ecall::placeholder::TODO_KZG_POINT_EVAL);
    ZKVM_EFAIL
}
