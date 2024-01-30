#![no_main]

extern crate succinct_zkvm;
use succinct_zkvm::syscall::syscall_keccak256_permute;

succinct_zkvm::entrypoint!(main);

pub fn main() {
    let mut state = [1u64; 25];
    syscall_keccak256_permute(state.as_mut_ptr());
    println!("{:?}", state);
}
