#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::syscalls::sys_write;

// #[allow(unused_unsafe)]
// #[no_mangle]
// pub fn sys_write(fd: u32, write_buf: *const u8, nbytes: usize) {
//     unsafe {
//         syscall_write(fd, write_buf, nbytes);
//     }
// }

pub fn main() {
    println!("Hello, world!");
    let string = "Hello, world 2!\n";
    sys_write(1, string.as_ptr(), string.len());
}
