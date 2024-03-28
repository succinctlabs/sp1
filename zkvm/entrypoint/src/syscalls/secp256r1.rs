#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Adds two Secp256r1 points.
///
/// The result is stored in the first point.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_secp256r1_add(p: *mut u32, q: *mut u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::SECP256R1_ADD,
            in("a0") p,
            in("a1") q
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Double a Secp256r1 point.
///
/// The result is stored in the first point.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_secp256r1_double(p: *mut u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::SECP256R1_DOUBLE,
            in("a0") p,
            in("a1") 0
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
