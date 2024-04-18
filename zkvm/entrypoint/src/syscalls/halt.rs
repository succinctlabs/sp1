cfg_if::cfg_if! {
    if #[cfg(target_os = "zkvm")] {
        use core::arch::asm;
        use p3_field::PrimeField32;
        use sha2::Digest;
        use crate::syscalls::PV_DIGEST_NUM_WORDS;
        use crate::syscalls::POSEIDON_NUM_WORDS;
        use crate::zkvm;
    }
}

/// Halts the program.
#[allow(unused_variables)]
pub extern "C" fn syscall_halt(exit_code: u8) -> ! {
    #[cfg(target_os = "zkvm")]
    unsafe {
        // When we halt, we retrieve the public values finalized digest.  This is the hash of all
        // the bytes written to the public values fd.
        let pv_digest_bytes = core::mem::take(&mut zkvm::PUBLIC_VALUES_HASHER)
            .unwrap()
            .finalize();

        // Convert the digest bytes into words, since we will be calling COMMIT ecall with
        // the words as a parameter.
        let pv_digest_words: [u32; PV_DIGEST_NUM_WORDS] = pv_digest_bytes
            .as_slice()
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // For each digest word, call COMMIT ecall.  In the runtime, this will store the digest words
        // into the runtime's execution record's public values digest.  In the AIR, it will be used
        // to verify that the provided public values digest matches the one computed by the program.
        for i in 0..PV_DIGEST_NUM_WORDS {
            asm!("ecall", in("t0") crate::syscalls::COMMIT, in("a0") i, in("a1") pv_digest_words[i]);
        }

        let deferred_proofs_digest;
        unsafe {
            deferred_proofs_digest = zkvm::DEFERRED_PROOFS_DIGEST.as_mut().unwrap();
        }
        let deferred_proofs_digest_words = deferred_proofs_digest
            .iter()
            .map(|baby_bear| baby_bear.as_canonical_u32());

        for i in 0..POSEIDON_NUM_WORDS {
            asm!("ecall", in("t0") crate::syscalls::COMMIT_DEFERRED_PROOFS, in("a0") i, in("a1") pv_digest_words[i]);
        }

        asm!(
            "ecall",
            in("t0") crate::syscalls::HALT,
            in("a0") exit_code
        );
        unreachable!()
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
