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
