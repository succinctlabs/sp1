#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Executes the Blake2f compress operation.
///
/// ### Safety
///
/// The caller must ensure that `w` is valid pointer to data that is aligned along a four byte
/// boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_blake2f_compress(state: *mut [u32; 213]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::BLAKE2F_COMPRESS,
            in("a0") state,
            in("a1") 0
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
