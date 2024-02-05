#![allow(unused_variables)]

#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Halts the program.
pub const HALT: u32 = 100;

/// Loads a word supplied from the prover.
pub const LWA: u32 = 101;

/// Executes `SHA_EXTEND`.
pub const SHA_EXTEND: u32 = 102;

/// Executes `SHA_COMPRESS`.
pub const SHA_COMPRESS: u32 = 103;

/// Executes `ED_ADD`.
pub const ED_ADD: u32 = 104;

/// Executes `ED_DECOMPRESS`.
pub const ED_DECOMPRESS: u32 = 105;

/// Executes `KECCAK_PERMUTE`.
pub const KECCAK_PERMUTE: u32 = 106;

/// Executes `SECP256K1_ADD`.
pub const SECP256K1_ADD: u32 = 107;

/// Executes `SECP256K1_DOUBLE`.
pub const SECP256K1_DOUBLE: u32 = 108;

/// Executes `K256_DECOMPRESS`.
pub const SECP256K1_DECOMPRESS: u32 = 109;

/// Writes to a file descriptor. Currently only used for `STDOUT/STDERR`.
pub const WRITE: u32 = 999;

pub extern "C" fn syscall_halt() -> ! {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") HALT
        );
        unreachable!()
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

#[allow(unused_variables)]
pub extern "C" fn syscall_write(fd: u32, write_buf: *const u8, nbytes: usize) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") WRITE,
            in("a0") fd,
            in("a1") write_buf,
            in("a2") nbytes,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

#[allow(unused_variables)]
pub extern "C" fn syscall_read(fd: u32, read_buf: *mut u8, nbytes: usize) {
    let whole_words: usize = nbytes / 4;
    let remaining_bytes = nbytes % 4;

    for i in 0..whole_words {
        let offset = i * 4;
        #[cfg(target_os = "zkvm")]
        unsafe {
            let mut word;
            asm!(
                "ecall",
                in("t0") LWA,
                in("a0") fd,
                in("a1") 4, // The number of bytes we're requesting
                lateout("a0") word,
            );

            // Copy the word into the read buffer
            let word_ptr = &mut word as *mut u32 as *mut u8;
            for j in 0..4 {
                *read_buf.add(offset + j) = *word_ptr.add(j);
            }
        }
    }

    // Handle the remaining bytes for the last partial word
    if remaining_bytes > 0 {
        let offset = whole_words * 4;
        #[cfg(target_os = "zkvm")]
        unsafe {
            let mut word;
            asm!(
                "ecall",
                in("t0") LWA,
                in("a0") fd,
                in("a1") remaining_bytes, // Request the remaining bytes
                lateout("a0") word,
            );

            // Copy the necessary bytes of the word into the read buffer
            let word_ptr = &mut word as *mut u32 as *mut u8;
            for j in 0..remaining_bytes {
                *read_buf.add(offset + j) = *word_ptr.add(j);
            }
        }
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_sha256_extend(w: *mut u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") SHA_EXTEND,
            in("a0") w
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_sha256_compress(w: *mut u32, state: *mut u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        let mut w_and_h = [0u32; 72];
        let w_slice = std::slice::from_raw_parts_mut(w, 64);
        let h_slice = std::slice::from_raw_parts_mut(state, 8);
        w_and_h[0..64].copy_from_slice(w_slice);
        w_and_h[64..72].copy_from_slice(h_slice);
        asm!(
            "ecall",
            in("t0") SHA_COMPRESS,
            in("a0") w_and_h.as_ptr()
        );
        for i in 0..64 {
            *w.add(i) = w_and_h[i];
        }
        for i in 0..8 {
            *state.add(i) = w_and_h[64 + i];
        }
    }
}

#[allow(unused_variables)]
#[no_mangle]
/// Adds two Edwards points. The result is stored in the first point.
pub extern "C" fn syscall_ed_add(p: *mut u32, q: *mut u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") ED_ADD,
            in("a0") p,
            in("a1") q
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

#[allow(unused_variables)]
#[no_mangle]
/// Decompresses a compressed Edwards point. The second half of the input array should contain the
/// compressed Y point with the final bit as the sign bit. The first half of the input array will
/// be overwritten with the decompressed point, and the sign bit will be removed.
pub extern "C" fn syscall_ed_decompress(point: &mut [u8; 64]) {
    #[cfg(target_os = "zkvm")]
    {
        let sign = point[63] >> 7;
        point[63] &= 0b0111_1111;
        point[31] = sign;
        let p = point.as_mut_ptr() as *mut u8;
        unsafe {
            asm!(
                "ecall",
                in("t0") ED_DECOMPRESS,
                in("a0") p,
            );
        }
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

#[allow(unused_variables)]
#[no_mangle]
/// Adds two Secp256k1 points. The result is stored in the first point.
pub extern "C" fn syscall_secp256k1_add(p: *mut u32, q: *mut u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") SECP256K1_ADD,
            in("a0") p,
            in("a1") q
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

#[allow(unused_variables)]
#[no_mangle]
/// Double a Secp256k1 point. The result is stored in the first point.
pub extern "C" fn syscall_secp256k1_double(p: *mut u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") SECP256K1_DOUBLE,
            in("a0") p,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

#[allow(unused_variables)]
#[no_mangle]
/// Decompresses a compressed Secp256k1 point. The input array should be 32 bytes long, with the
/// first 16 bytes containing the X coordinate in big-endian format. The second half of the input
/// will be overwritten with the decompressed point.
pub extern "C" fn syscall_secp256k1_decompress(point: &mut [u8; 64], is_odd: bool) {
    #[cfg(target_os = "zkvm")]
    {
        // Memory system/FpOps are little endian so we'll just flip the whole array before/after
        point.reverse();
        point[0] = is_odd as u8;
        let p = point.as_mut_ptr();
        unsafe {
            asm!(
                "ecall",
                in("t0") SECP256K1_DECOMPRESS,
                in("a0") p,
            );
        }
        point.reverse();
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_keccak_permute(state: *mut u64) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") KECCAK_PERMUTE,
            in("a0") state
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn sys_panic(msg_ptr: *const u8, len: usize) -> ! {
    sys_write(2, msg_ptr, len);
    syscall_halt();
}

#[no_mangle]
pub fn sys_getenv(
    recv_buf: *mut u32,
    words: usize,
    varname: *const u8,
    varname_len: usize,
) -> usize {
    0
}

#[no_mangle]
pub fn sys_alloc_words(nwords: usize) -> *mut u32 {
    core::ptr::null_mut()
}

#[no_mangle]
pub fn sys_write(fd: u32, write_buf: *const u8, nbytes: usize) {
    syscall_write(fd, write_buf, nbytes);
}
