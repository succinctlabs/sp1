#![no_main]
extern crate succinct_zkvm;
succinct_zkvm::entrypoint!(main);

use succinct_zkvm::syscall::syscall_keccak256_permute;

pub fn main() {
    let mut state = [1u64; 25];
    syscall_keccak256_permute(state.as_mut_ptr());
    println!("{:?}", state);
}
