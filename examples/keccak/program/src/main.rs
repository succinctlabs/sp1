#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::syscalls::syscall_keccak_permute;

pub fn main() {
    // Number of Keccak-f permutations to run.
    let n = sp1_zkvm::io::read::<u32>();

    let mut state = [1u64; 25];
    for _ in 0..n {
        syscall_keccak_permute(&mut state);
    }

    sp1_zkvm::io::commit(&state);
}
