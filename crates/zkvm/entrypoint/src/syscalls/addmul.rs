#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Uint256 multiplication operation.
///
/// The result is written over the first input.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_add_mul(x: *const u32, y: *const u32, p: *const u32, q: *const u32, e: *mut u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::ADDMUL,
            in("a0") x,
            in("a1") y,
            in("a2") p,
            in("a3") q,
            in("a4") e
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
