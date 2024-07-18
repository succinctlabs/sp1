use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(target_os = "zkvm")] {
        use core::arch::asm;
        use sha2::Digest;
        use crate::zkvm;
        use crate::{PV_DIGEST_NUM_WORDS, POSEIDON_NUM_WORDS};
    }
}

cfg_if! {
    if #[cfg(all(target_os = "zkvm", feature = "verify"))] {
        use p3_field::PrimeField32;
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

        // For each digest word, call COMMIT ecall.  In the runtime, this will store the digest words
        // into the runtime's execution record's public values digest.  In the AIR, it will be used
        // to verify that the provided public values digest matches the one computed by the program.
        for i in 0..PV_DIGEST_NUM_WORDS {
            // Convert the digest bytes into words, since we will call COMMIT one word at a time.
            let word = u32::from_le_bytes(pv_digest_bytes[i * 4..(i + 1) * 4].try_into().unwrap());
            asm!("ecall", in("t0") crate::syscalls::COMMIT, in("a0") i, in("a1") word);
        }

        cfg_if! {
            if #[cfg(feature = "verify")] {
                let deferred_proofs_digest = zkvm::DEFERRED_PROOFS_DIGEST.as_mut().unwrap();

                for i in 0..POSEIDON_NUM_WORDS {
                    let word = deferred_proofs_digest[i].as_canonical_u32();
                    asm!("ecall", in("t0") crate::syscalls::COMMIT_DEFERRED_PROOFS, in("a0") i, in("a1") word);
                }
            } else {
                for i in 0..POSEIDON_NUM_WORDS {
                    asm!("ecall", in("t0") crate::syscalls::COMMIT_DEFERRED_PROOFS, in("a0") i, in("a1") 0);
                }
            }
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
