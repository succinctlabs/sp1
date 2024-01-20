#![no_main]

extern crate succinct_zkvm;
use succinct_zkvm::syscall::syscall_sha256_compress;

succinct_zkvm::entrypoint!(main);

pub fn main() {
    let mut w = [1u32; 64];
    let mut state = [1u32; 8];
    syscall_sha256_compress(w.as_mut_ptr(), state.as_mut_ptr());
    println!("{:?}", state);
}
