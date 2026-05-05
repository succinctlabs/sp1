#[cfg(target_os = "zkvm")]
use core::arch::asm;

cfg_if::cfg_if! {
    if #[cfg(target_os = "zkvm")] {
        use alloc::vec::Vec;
        use crate::syscalls::VERIFY_SP1_PROOF;
        use crate::zkvm::DEFERRED_PROOFS_DIGEST;
        use sp1_primitives::SP1Field;
        use slop_algebra::AbstractField;
        use sp1_primitives::hash_deferred_proof;
    }
}

#[no_mangle]
#[allow(unused_variables)]
pub fn syscall_verify_sp1_proof(vk_digest: &[u64; 4], pv_digest: &[u64; 4]) {
    #[cfg(target_os = "zkvm")]
    {
        // Call syscall to verify the next proof at runtime
        unsafe {
            asm!(
                "ecall",
                in("t0") VERIFY_SP1_PROOF,
                in("a0") vk_digest.as_ptr(),
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

        #[cfg(not(target_endian = "little"))]
        compile_error!("expected target to be little endian");
        // SAFETY: Arrays are always laid out in the obvious way. Any possible element value is
        // always valid. The pointee types have the same size, and the target of each transmute has
        // finer alignment than the source.
        // Although not a safety invariant, note that the guest target is always little-endian,
        // which was just sanity-checked, so this will always have the expected behavior.
        let vk_digest_koalabear =
            unsafe { core::mem::transmute::<&[u64; 4], &[u32; 8]>(vk_digest) }
                .map(SP1Field::from_canonical_u32);
        // Remaining 32 elements are pv_digest converted from u8 to KoalaBear
        let pv_digest_koalabear =
            unsafe { core::mem::transmute::<&[u64; 4], &[u8; 32]>(pv_digest) }
                .map(SP1Field::from_canonical_u8);

        *deferred_proofs_digest =
            hash_deferred_proof(deferred_proofs_digest, &vk_digest_koalabear, &pv_digest_koalabear);
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
