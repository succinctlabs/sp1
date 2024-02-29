#[cfg(target_os = "zkvm")]
use core::arch::asm;

#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_native_op(a: *mut u32, b: *mut u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::NATIVE,
            in("a0") a,
            in("a1") b
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
