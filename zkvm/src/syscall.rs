#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Halts the program.
pub const HALT: u32 = 100;

/// Loads a word supplied from the prover.
pub const LWA: u32 = 101;

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
    panic!()
}

#[no_mangle]
pub unsafe extern "C" fn sys_panic(_msg_ptr: *const u8, _len: usize) -> ! {
    unreachable!()
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
pub fn sys_write(fd: u32, write_buf: *const u8, nbytes: usize) {}
