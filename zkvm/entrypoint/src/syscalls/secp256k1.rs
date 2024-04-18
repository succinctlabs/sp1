#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Adds two Secp256k1 points.
///
/// The result is stored in the first point.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_secp256k1_add(p: *mut u32, q: *mut u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::SECP256K1_ADD,
            in("a0") p,
            in("a1") q
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Double a Secp256k1 point.
///
/// The result is stored in the first point.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_secp256k1_double(p: *mut u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::SECP256K1_DOUBLE,
            in("a0") p,
            in("a1") 0
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Decompresses a compressed Secp256k1 point.
///
/// The input array should be 32 bytes long, with the first 16 bytes containing the X coordinate in
/// big-endian format. The second half of the input will be overwritten with the decompressed point.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_secp256k1_decompress(point: &mut [u8; 64], is_odd: bool) {
    #[cfg(target_os = "zkvm")]
    {
        // Memory system/FpOps are little endian so we'll just flip the whole array before/after
        point.reverse();
        let p = point.as_mut_ptr();
        unsafe {
            asm!(
                "ecall",
                in("t0") crate::syscalls::SECP256K1_DECOMPRESS,
                in("a0") p,
                in("a1") is_odd as u8
            );
        }
        point.reverse();
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
