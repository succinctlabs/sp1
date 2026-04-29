#[cfg(target_os = "zkvm")]
use core::arch::asm;

#[no_mangle]
pub fn syscall_enter_unconstrained() -> bool {
    #[allow(unused_mut)]
    let mut continue_unconstrained: u32;
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::ENTER_UNCONSTRAINED,
            lateout("t0") continue_unconstrained,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    {
        // Host-only no-op (sp1-zkvm is `#![no_std]` so eprintln! is not
        // available; the only consumer of this code path on host is
        // type-check, not actual execution).
        continue_unconstrained = 1;
    }

    continue_unconstrained == 1
}

#[no_mangle]
pub fn syscall_exit_unconstrained() {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::EXIT_UNCONSTRAINED,
        );
        unreachable!()
    }

    // Host-only no-op (see comment in `syscall_enter_unconstrained`).
    #[cfg(not(target_os = "zkvm"))]
    {}
}
