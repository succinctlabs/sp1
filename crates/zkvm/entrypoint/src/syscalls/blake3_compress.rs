#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Executes the Blake3 inner compression function on the given state and message.
///
/// ### Safety
///
/// The caller must ensure that `state` is a valid pointer to a 16-element u64 array and
/// `msg` is a valid pointer to a 16-element u64 array, both aligned on an eight-byte boundary.
/// Each u64 element holds a single u32 Blake3 word in its lower 32 bits (upper 32 bits zero).
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_blake3_compress_inner(state: *mut u64, msg: *const u64) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::BLAKE3_COMPRESS_INNER,
            in("a0") state,
            in("a1") msg,
        );
    }
}
