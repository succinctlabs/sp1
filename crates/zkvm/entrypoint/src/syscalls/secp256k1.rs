#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Adds two Secp256k1 points.
///
/// The result is stored in the first point.
///
/// ### Safety
///
/// The caller must ensure that `p` and `q` are valid pointers to data that is aligned along an
/// eight byte boundary. Additionally, the caller must ensure that `p` and `q` are valid points on
/// the secp256k1 curve, and that `p` and `q` are not equal to each other.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_secp256k1_add(p: *mut [u64; 8], q: *mut [u64; 8]) {
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

/// Multiply a Secp256k1 point by a scalar.
///
/// The scalar is a 256-bit `BigUint` stored as 4 little-endian `u64` limbs. The result is stored
/// in-place in `p`, i.e. `p ← scalar * p`.
///
/// ### Safety
///
/// The caller must ensure that `p` and `scalar` are valid pointers to data that is aligned along
/// an eight byte boundary, and that `p` is a valid point on the secp256k1 curve.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_secp256k1_mul(p: *mut [u64; 8], scalar: *const [u64; 4]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::SECP256K1_MUL,
            in("a0") p,
            in("a1") scalar,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Double a Secp256k1 point.
///
/// The result is stored in-place in the supplied buffer.
///
/// ### Safety
///
/// The caller must ensure that `p` is valid pointer to data that is aligned along an eight byte
/// boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_secp256k1_double(p: *mut [u64; 8]) {
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
/// The array represents two field elements. When considered as a byte array, the representation is
/// big-endian. This means that the `u64`s are actually byte-reversed due to the little-endian
/// architecture. The reason the type signature requires a u64 array is because we want the pointers
/// to be aligned to the architecture's register bit widths.
///
/// The input array should be 64 bytes long, with the first 32 bytes containing the X coordinate.
/// The second half of the input will be overwritten with the Y coordinate of the decompressed point
/// using the point's parity (is_odd).
///
/// ### Safety
///
/// The caller must ensure that `point` is valid pointer to data that is aligned along an eight byte
/// boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_secp256k1_decompress(point: &mut [u64; 8], is_odd: bool) {
    #[cfg(target_os = "zkvm")]
    {
        // SAFETY: Both pointee types have the same size. The destination has a finer alignment than
        // the source.
        let point = unsafe { core::mem::transmute::<&mut [u64; 8], &mut [u8; 64]>(point) };
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
