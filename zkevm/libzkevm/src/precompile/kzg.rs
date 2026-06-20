//! KZG point evaluation — Ethereum precompile 0x0a (EIP-4844).

use crate::precompile::types::{KzgCommitment, KzgFieldElement, KzgProof as ZkvmKzgProof};
use crate::status::{ZKVM_EFAIL, ZKVM_EOK};
use kzg_rs::{Bytes32, Bytes48, KzgProof, KzgSettings};

/// `zkvm_status zkvm_kzg_point_eval(commitment, z, y, proof, verified)`.
///
/// Verifies a KZG opening for blob commitments per EIP-4844. The
/// underlying pairing check `e(C - [y]_1, G2) == e(proof, [tau]_2 - [z]_2)`
/// runs on top of the patched `bls12_381` crate (i.e. SP1's `BLS12381_*`
/// syscalls at `target_os = "zkvm"`); the trusted-setup G2 point
/// `[tau]_2` is baked in via `kzg-rs`'s precomputed `KzgSettings`.
///
/// Layout per `zkvm_accelerators.h`: `commitment` and `proof` are
/// 48-byte compressed G1; `z` and `y` are 32-byte big-endian field
/// elements modulo the BLS12-381 group order.
///
/// On parse error or pairing-check failure the function still returns
/// `ZKVM_EOK` with `*verified = false` — only true API misuse (null
/// pointers) surfaces as `ZKVM_EFAIL`.
#[no_mangle]
pub unsafe extern "C" fn zkvm_kzg_point_eval(
    commitment: *const KzgCommitment,
    z: *const KzgFieldElement,
    y: *const KzgFieldElement,
    proof: *const ZkvmKzgProof,
    verified: *mut bool,
) -> i32 {
    if commitment.is_null() || z.is_null() || y.is_null() || proof.is_null() || verified.is_null() {
        return ZKVM_EFAIL;
    }

    let commitment_bytes = Bytes48((*commitment).data);
    let z_bytes = Bytes32((*z).data);
    let y_bytes = Bytes32((*y).data);
    let proof_bytes = Bytes48((*proof).data);

    let settings = match KzgSettings::load_trusted_setup_file() {
        Ok(s) => s,
        Err(_) => {
            *verified = false;
            return ZKVM_EOK;
        }
    };

    *verified = matches!(
        KzgProof::verify_kzg_proof(&commitment_bytes, &z_bytes, &y_bytes, &proof_bytes, &settings),
        Ok(true)
    );
    ZKVM_EOK
}
