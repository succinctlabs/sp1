#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Decompresses a compressed BLS12-381 point.
///
/// The first half of the input array should contain the compressed X point. The first byte of the second part contains the sign.
/// The second half of the input array will be overwritten with the decompressed point,
/// and the sign bit will be removed.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_decompress(point: &mut [u8; 96]) {
    #[cfg(target_os = "zkvm")]
    {
        let sign = point[0] & 0b_1110_0000;
        point[0] &= 0b_0001_1111;

        // Memory system/FpOps are little endian so we'll just flip the whole array before/after
        point.reverse();

        let p = point.as_mut_ptr() as *mut u8;
        unsafe {
            asm!(
                "ecall",
                in("t0") crate::syscalls::BLS12381_DECOMPRESS,
                in("a0") p,
                in("a1") sign,
            );
        }
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
