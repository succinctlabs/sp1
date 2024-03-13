#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// BigUint addition operation.
///
/// The result is written over the first input.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_biguint_add(x: *mut u32, y: *mut u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::BLAKE3_COMPRESS_INNER,
            in("a0") x,
            in("a1") y,
            in("a2") 0u32,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// BigUint subtraction operation.
///
/// The result is written over the first input.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_biguint_sub(x: *mut u32, y: *mut u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::BLAKE3_COMPRESS_INNER,
            in("a0") x,
            in("a1") y,
            in("a2") 1u32,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// BigUint multiplication operation.
///
/// The result is written over the first input.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_biguint_mul(x: *mut u32, y: *mut u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::BLAKE3_COMPRESS_INNER,
            in("a0") x,
            in("a1") y,
            in("a2") 2u32,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
