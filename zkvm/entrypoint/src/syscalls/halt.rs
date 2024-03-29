#[cfg(target_os = "zkvm")]
use core::arch::asm;

use crate::PiDigest;

/// Halts the program.
#[allow(unused_variables)]
pub extern "C" fn syscall_halt(exit_code: u8, pi_digest: &PiDigest<u32>) -> ! {
    #[cfg(target_os = "zkvm")]
    unsafe {
        for i in 0..PI_DIGEST_NUM_WORDS {
            asm!("ecall", in("t0") crate::syscalls::COMMIT, in("a0") i, in("a1") pi_digest[i]);
        }

        asm!(
            "ecall",
            in("t0") crate::syscalls::HALT,
            in("a0") exit_code,
        );
        unreachable!()
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
