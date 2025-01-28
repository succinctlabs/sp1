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
        eprintln!("Entering unconstrained execution block");
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

    #[cfg(not(target_os = "zkvm"))]
    eprintln!("Exiting unconstrained execution block");
}
