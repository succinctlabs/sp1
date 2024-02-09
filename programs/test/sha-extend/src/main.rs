#![no_main]
extern crate succinct_zkvm;
succinct_zkvm::entrypoint!(main);

use succinct_zkvm::syscalls::syscall_sha256_extend;

pub fn main() {
    let mut w = [1u32; 64];
    syscall_sha256_extend(w.as_mut_ptr());
    println!("{:?}", w);
}
