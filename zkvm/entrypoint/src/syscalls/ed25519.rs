#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Adds two Edwards points.
///
/// The result is stored in the first point.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_ed_add(p: *mut u32, q: *mut u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::ED_ADD,
            in("a0") p,
            in("a1") q
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Decompresses a compressed Edwards point.
///
/// The second half of the input array should contain the compressed Y point with the final bit as
/// the sign bit. The first half of the input array will be overwritten with the decompressed point,
/// and the sign bit will be removed.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_ed_decompress(point: &mut [u8; 64]) {
    #[cfg(target_os = "zkvm")]
    {
        let sign = point[63] >> 7;
        point[63] &= 0b0111_1111;
        let p = point.as_mut_ptr() as *mut u8;
        unsafe {
            asm!(
                "ecall",
                in("t0") crate::syscalls::ED_DECOMPRESS,
                in("a0") p,
                in("a1") sign
            );
        }
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
