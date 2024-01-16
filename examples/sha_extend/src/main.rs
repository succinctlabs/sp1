#![no_main]

extern crate curta_zkvm;
use curta_zkvm::syscall::{syscall_halt, syscall_sha_extend};

curta_zkvm::entry!(main);

pub fn main() {
    let mut w = [0u32; 64];
    syscall_sha_extend(w.as_mut_ptr());
    syscall_halt();
}
