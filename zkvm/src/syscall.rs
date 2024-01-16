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

pub extern "C" fn syscall_sha_extend(w: *mut u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") SHA_EXTEND,
            in("a0") w
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unsafe {
        for i in 16..64 {
            let s0 = (*w.add(i - 15)).rotate_right(7)
                ^ (*w.add(i - 15)).rotate_right(18)
                ^ (*w.add(i - 15) >> 3);
            let s1 = (*w.add(i - 2)).rotate_right(17)
                ^ (*w.add(i - 2)).rotate_right(19)
                ^ ((*w.add(i - 2)) >> 10);
            *w.add(i) = (*w.add(i - 16))
                .wrapping_add(s0)
                .wrapping_add(*w.add(i - 7))
                .wrapping_add(s1);
        }
    }
}

pub extern "C" fn syscall_sha_compress(w: *mut u32, state: *mut u32) {
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
    }

    #[cfg(not(target_os = "zkvm"))]
    unsafe {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let w = std::slice::from_raw_parts_mut(w, 64);
        let h = std::slice::from_raw_parts_mut(state, 8);
        for i in 0..64 {
            let ch = (h[4] & h[5]) ^ (!h[4] & h[6]);
            let ma = (h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]);
            let s0 = h[0].rotate_right(2) ^ h[0].rotate_right(13) ^ h[0].rotate_right(22);
            let s1 = h[4].rotate_right(6) ^ h[4].rotate_right(11) ^ h[4].rotate_right(25);
            let t0 = h[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let t1 = s0.wrapping_add(ma);

            h[7] = h[6];
            h[6] = h[5];
            h[5] = h[4];
            h[4] = h[3].wrapping_add(t0);
            h[3] = h[2];
            h[2] = h[1];
            h[1] = h[0];
            h[0] = t0.wrapping_add(t1);
        }

        for (i, v) in h.iter_mut().enumerate() {
            *v = v.wrapping_add(*state.add(i));
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn sys_panic(_msg_ptr: *const u8, _len: usize) -> ! {
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
    return core::ptr::null_mut();
}

#[no_mangle]
pub fn sys_write(fd: u32, write_buf: *const u8, nbytes: usize) {
    syscall_write(fd, write_buf, nbytes);
}
