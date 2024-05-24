use crate::syscalls::{syscall_halt, syscall_write};

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn sys_panic(msg_ptr: *const u8, len: usize) -> ! {
    sys_write(2, msg_ptr, len);
    syscall_halt(1);
}

#[allow(unused_variables)]
#[no_mangle]
pub const fn sys_getenv(
    recv_buf: *mut u32,
    words: usize,
    varname: *const u8,
    varname_len: usize,
) -> usize {
    0
}

#[allow(unused_variables)]
#[no_mangle]
pub const fn sys_alloc_words(nwords: usize) -> *mut u32 {
    core::ptr::null_mut()
}

#[allow(unused_unsafe)]
#[no_mangle]
pub fn sys_write(fd: u32, write_buf: *const u8, nbytes: usize) {
    unsafe {
        syscall_write(fd, write_buf, nbytes);
    }
}
