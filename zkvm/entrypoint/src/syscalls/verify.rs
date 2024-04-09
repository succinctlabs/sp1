#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// The number of 32 bit words that the public values digest is composed of.
pub const PV_DIGEST_NUM_WORDS: usize = 8;

pub const POSEIDON_NUM_WORDS: usize = 8;
use crate::zkvm::DEFERRED_PROOFS_DIGEST;
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use sp1_primitives::{poseidon2_hash, POSEIDON2_HASHER};

#[no_mangle]
pub fn syscall_verify_sp1_proof(vkey: &[u32; 8], proof: *const u8, proof_len: usize) {
    let ptrs = [vkey.as_ptr() as *const u8, proof];
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::VERIFY_SP1_PROOF,
            in("a0") ptrs.as_ptr(),
            in("a1") proof_len,
        );
    }

    // Update deferred_proofs_digest to be poseidon2_hash(deferred_proofs_digest || vkey || proof)
    let mut hash_input = Vec::with_capacity(16 + proof_len);
    // First 8 bytes are previous hash (initially zero bytes)
    let deferred_proofs_digest;
    // SAFETY: we have sole access because zkvm is single threaded.
    unsafe {
        // hash_input.extend_from_slice(DEFERRED_PROOFS_DIGEST.as_ref().unwrap());
        deferred_proofs_digest = DEFERRED_PROOFS_DIGEST.as_mut().unwrap();
        hash_input.extend_from_slice(deferred_proofs_digest);
    }
    // Next 8 bytes are vkey converted from u32s to BabyBear
    let vkey_baby_bear = vkey
        .iter()
        .flat_map(|x| {
            x.to_le_bytes()
                .iter()
                .map(|b| BabyBear::from_canonical_u8(*b))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    hash_input.extend_from_slice(&vkey_baby_bear);
    // Remaining bytes are proof converted from u32s to BabyBear
    // SAFETY: we assume the caller has provided a valid proof pointer and length.
    let proof_slice = unsafe { core::slice::from_raw_parts(proof, proof_len) };
    let proof_baby_bear = proof_slice
        .iter()
        .flat_map(|x| {
            x.to_le_bytes()
                .iter()
                .map(|b| BabyBear::from_canonical_u8(*b))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    hash_input.extend_from_slice(&proof_baby_bear);

    *deferred_proofs_digest = poseidon2_hash(hash_input);

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
