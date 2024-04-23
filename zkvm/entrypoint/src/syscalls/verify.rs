#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// The number of 32 bit words that the public values digest is composed of.
pub const PV_DIGEST_NUM_WORDS: usize = 8;

pub const POSEIDON_NUM_WORDS: usize = 8;

cfg_if::cfg_if! {
    if #[cfg(target_os = "zkvm")] {
        use crate::syscalls::VERIFY_SP1_PROOF;
        use crate::zkvm::DEFERRED_PROOFS_DIGEST;
        use p3_baby_bear::BabyBear;
        use p3_field::AbstractField;
        use sp1_primitives::poseidon2_hash;
    }
}

#[no_mangle]
#[allow(unused_variables)]
pub fn syscall_verify_sp1_proof(vkey: &[u32; 8], pv_digest: &[u32; 8]) {
    #[cfg(target_os = "zkvm")]
    {
        // Call syscall to verify the next proof at runtime
        unsafe {
            asm!(
                "ecall",
                in("t0") crate::syscalls::VERIFY_SP1_PROOF,
                in("a0") vkey.as_ptr(),
                in("a1") pv_digest.as_ptr(),
            );
        }

        // Update digest to p2_hash(prev_digest[0..8] || vkey_digest[0..8] || pv_digest[0..32])
        let mut hash_input = Vec::with_capacity(48);
        // First 8 elements are previous hash (initially zero)
        let deferred_proofs_digest;
        // SAFETY: we have sole access because zkvm is single threaded.
        unsafe {
            deferred_proofs_digest = DEFERRED_PROOFS_DIGEST.as_mut().unwrap();
        }
        hash_input.extend_from_slice(deferred_proofs_digest);
        // Next 8 elements are vkey_digest
        let vkey_baby_bear = vkey
            .iter()
            .map(|x| BabyBear::from_canonical_u32(*x))
            .collect::<Vec<_>>();
        hash_input.extend_from_slice(&vkey_baby_bear);
        // Remaining 32 elements are pv_digest converted from u32s to BabyBear
        let pv_digest_baby_bear = pv_digest
            .iter()
            .flat_map(|x| {
                x.to_le_bytes()
                    .iter()
                    .map(|b| BabyBear::from_canonical_u8(*b))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        hash_input.extend_from_slice(&pv_digest_baby_bear);

        *deferred_proofs_digest = poseidon2_hash(hash_input);
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
