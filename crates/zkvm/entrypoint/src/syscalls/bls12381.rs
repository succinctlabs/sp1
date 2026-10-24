#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Adds two Bls12381 points.
///
/// The result is stored in the first point.
///
/// ### Safety
///
/// The caller must ensure that `p` and `q` are valid pointers to data that is aligned along an
/// eight byte boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_add(p: *mut [u64; 12], q: *const [u64; 12]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::BLS12381_ADD,
            in("a0") p,
            in("a1") q,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Double a Bls12381 point.
///
/// The result is stored in the first point.
///
/// ### Safety
///
/// The caller must ensure that `p` is valid pointer to data that is aligned along an eight byte
/// boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_double(p: *mut [u64; 12]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::BLS12381_DOUBLE,
            in("a0") p,
            in("a1") 0,
        );
    }
}

/// Decompresses a compressed BLS12-381 point.
///
/// The array represents two field elements. When considered as a byte array, the representation is
/// big-endian. This means that the `u64`s are actually byte-reversed due to the little-endian
/// architecture. The reason the type signature requires a u64 array is because we want the pointers
/// to be aligned to the architecture's register bit widths.
///
/// The first half of the input array should contain the X coordinate. The second half of the input
/// array will be overwritten with the Y coordinate.
///
/// ### Safety
///
/// The caller must ensure that `point` is valid pointer to data that is aligned along an eight byte
/// boundary.
///
/// # Deprecated
///
/// The `BLS12381_DECOMPRESS` precompile is decommissioned: it has no executor implementation
/// and no AIR, so the `ecall` below traps the executor on every input.
#[deprecated = "the BLS12381_DECOMPRESS precompile is decommissioned (no executor \
                implementation, no AIR); every call traps the executor. See \
                https://github.com/succinctlabs/sp1/issues/2926"]
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_decompress(point: &mut [u64; 12], sign_bit: bool) {
    #[cfg(target_os = "zkvm")]
    {
        // SAFETY: Both pointee types have the same size. The destination has a finer alignment than
        // the source.
        let point = unsafe { core::mem::transmute::<&mut [u64; 12], &mut [u8; 12 * 8]>(point) };
        // Memory system/FpOps are little endian so we'll just flip the whole array before/after
        point.reverse();
        let p = point.as_mut_ptr();
        unsafe {
            asm!(
                "ecall",
                in("t0") crate::syscalls::BLS12381_DECOMPRESS,
                in("a0") p,
                in("a1") sign_bit as u8,
            );
        }
        point.reverse();
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
