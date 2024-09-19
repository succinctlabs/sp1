#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Uint256 multiplication operation.
///
/// The result is written over the first input.
///
/// ### Safety
///
/// The caller must ensure that `x` and `y` are valid pointers to data that is aligned along a four
/// byte boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_u256x2048_mul(
    a: *const [u32; 8],
    b: *const [u32; 64],
    lo: *mut [u32; 64],
    hi: *mut [u32; 8],
) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::U256XU2048_MUL,
            in("a0") a,
            in("a1") b,
            in("a2") lo,
            in("a3") hi,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
