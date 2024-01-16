#![no_main]

extern crate curta_zkvm;
use curta_zkvm::syscall::syscall_sha256_extend;

curta_zkvm::entrypoint!(main);

pub fn main() {
    let mut w = [1u32; 64];
    println!("{:?}", w);
    // syscall_sha256_extend(w.as_mut_ptr());
    // for i in 0..64 {
    //     println!("{}", w[i]);
    // }
}
