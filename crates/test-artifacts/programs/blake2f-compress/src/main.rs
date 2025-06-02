#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::syscalls::syscall_blake2f_compress;

pub fn main() {
    let mut state = [1u32; 212];

    syscall_blake2f_compress(&mut state);

    println!("{:?}", state);
}
