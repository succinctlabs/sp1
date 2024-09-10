use crate::syscall_verify_sp1_proof;
use gnark_bn254_verifier::{PlonkVerifier, Verifier};
use substrate_bn::Fr;

/// Verifies the next proof in the proof input stream given a verification key digest and public
/// values digest. If the proof is invalid, the function will panic.
///
/// Enable this function by adding the `verify` feature to both the `sp1-lib` AND `sp1-zkvm` crates.
pub fn verify_sp1_proof(vk_digest: &[u32; 8], pv_digest: &[u8; 32]) {
    unsafe {
        syscall_verify_sp1_proof(vk_digest, pv_digest);
    }
}

/// Verifies a plonk proof given the proof, verification key, verification key hash, and committed
/// values digest bytes. If the proof is invalid, the function will panic.
///
/// Enable this function by adding the `verify` feature to both the `sp1-lib` AND `sp1-zkvm` crates.

pub fn verify_plonk_proof(
    proof: &[u8],
    vk: &[u8],
    vkey_hash: &[u8],
    committed_values_digest_bytes: &[u8],
) {
    let vkey_hash = Fr::from_slice(vkey_hash).expect("Unable to read vkey_hash");
    let committed_values_digest = Fr::from_slice(committed_values_digest_bytes)
        .expect("Unable to read committed_values_digest");

    if !PlonkVerifier::verify(proof, vk, &[vkey_hash, committed_values_digest]) {
        panic!("Verification failed");
    }
}
