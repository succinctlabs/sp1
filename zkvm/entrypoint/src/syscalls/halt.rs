#[cfg(target_os = "zkvm")]
use core::arch::asm;

use crate::PI_DIGEST_SIZE;

/// Halts the program.
#[allow(unused_variables)]
pub extern "C" fn syscall_halt(exit_code: u8, pi_digest: *const [u8; PI_DIGEST_SIZE]) -> ! {
    #[cfg(target_os = "zkvm")]
    unsafe {
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
