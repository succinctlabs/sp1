#![no_main]
curta_zkvm::entrypoint!(main);

use curta_zkvm::syscalls::syscall_sha256_extend;

pub fn main() {
    let mut w = [1u32; 64];
    syscall_sha256_extend(w.as_mut_ptr());
    println!("{:?}", w);
}
