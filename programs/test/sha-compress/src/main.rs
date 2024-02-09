#![no_main]
extern crate succinct_zkvm;
succinct_zkvm::entrypoint!(main);

use succinct_zkvm::syscalls::syscall_sha256_compress;

pub fn main() {
    let mut w = [1u32; 64];
    let mut state = [1u32; 8];
    syscall_sha256_compress(w.as_mut_ptr(), state.as_mut_ptr());
    println!("{:?}", state);
}
