#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::syscalls::{syscall_sha256_compress, syscall_sha256_extend};

pub fn main() {
    // Number of SHA-256 (extend + compress) permutations to run.
    let n = sp1_zkvm::io::read::<u32>();

    let mut w = [1u64; 64];
    let mut state = [1u64; 8];

    for _ in 0..n {
        syscall_sha256_extend(&mut w);
        syscall_sha256_compress(&mut w, &mut state);
    }

    sp1_zkvm::io::commit(&state);
}
