#![no_main]

extern crate curta_zkvm;
use curta_zkvm::syscall::syscall_sha256_extend;

curta_zkvm::entrypoint!(main);

pub fn main() {
    let mut w = [1u32; 64];
    syscall_sha256_extend(w.as_mut_ptr());
    println!("{:?}", w);
}
