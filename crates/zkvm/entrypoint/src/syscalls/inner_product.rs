#[cfg(target_os = "zkvm")]
use core::arch::asm;
/// The result is written over the first input.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_inner_product(p: *mut u32, q: *mut u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::INNER_PRODUCT,
            in("a0") p,
            in("a1") q,
        );
    }
    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
