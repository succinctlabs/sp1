#[cfg(target_os = "zkvm")]
use core::arch::asm;

use crate::PI_DIGEST_WORD_SIZE;

/// Halts the program.
#[allow(unused_variables)]
pub extern "C" fn syscall_halt(exit_code: u8, pi_digest: &[u32; PI_DIGEST_WORD_SIZE]) -> ! {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!("add x20, x0, {0}", in(reg) pi_digest[0]);
        asm!("add x21, x0, {0}", in(reg) pi_digest[1]);
        asm!("add x22, x0, {0}", in(reg) pi_digest[2]);
        asm!("add x23, x0, {0}", in(reg) pi_digest[3]);
        asm!("add x24, x0, {0}", in(reg) pi_digest[4]);
        asm!("add x25, x0, {0}", in(reg) pi_digest[5]);
        asm!("add x26, x0, {0}", in(reg) pi_digest[6]);
        asm!("add x27, x0, {0}", in(reg) pi_digest[7]);

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
