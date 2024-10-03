#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::syscalls::syscall_sha256_extend;

pub fn main() {
    let mut w = [1u32; 64];
    syscall_sha256_extend(&mut w);
    syscall_sha256_extend(&mut w);
    syscall_sha256_extend(&mut w);
    println!("{:?}", w);
}
