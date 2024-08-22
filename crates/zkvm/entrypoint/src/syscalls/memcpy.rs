#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Executes the memcpy syscall on a destination pointer, a source pointer, and a number of bytes.
///
/// ### Safety
///
/// The caller must ensure that dst is more than nbytes away from src. In other words, the copy
/// must not overlap.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn call_memcpy(dst: *mut u8, src: *mut u8, nbytes: usize) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "call memcpy",
            in("a0") dst,
            in("a1") src,
            in("a2") nbytes,
        );
    }
}
