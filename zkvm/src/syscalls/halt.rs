#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Halts the program.
pub extern "C" fn syscall_halt() -> ! {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::HALT
        );
        unreachable!()
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
