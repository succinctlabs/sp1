#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Executes the SHA256 compress operation on the given word array and a given state.
///
/// ### Safety
///
/// The caller must ensure that `w` and `state` are valid pointers to data that is aligned along a
/// four byte boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_sha256_compress(w: *mut [u32; 64], state: *mut [u32; 8]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::SHA_COMPRESS,
            in("a0") w,
            in("a1") state,
        );
    }
}
