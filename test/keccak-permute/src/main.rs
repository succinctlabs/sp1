#![no_main]
curta_zkvm::entrypoint!(main);

use curta_zkvm::syscalls::syscall_keccak_permute;

pub fn main() {
    let mut state = [1u64; 25];
    syscall_keccak_permute(state.as_mut_ptr());
    println!("{:?}", state);
}
