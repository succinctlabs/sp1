#![no_main]

extern crate succinct_zkvm;
use succinct_zkvm::syscall::{syscall_halt, syscall_sha256_compress};

succinct_zkvm::entrypoint!(main);

pub fn main() {
    let mut w = [0u32; 64];
    let mut state = [0u32; 8];
    syscall_sha256_compress(w.as_mut_ptr(), state.as_mut_ptr());
    syscall_halt();
}
