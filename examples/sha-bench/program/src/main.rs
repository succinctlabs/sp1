#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::syscalls::{syscall_sha256_compress, syscall_sha256_extend};

pub fn main() {
    // SHA-256 initial hash values.
    let mut state: [u64; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // Hash 10 MB: 163840 blocks of 64 bytes each = 10,485,760 bytes.
    for block_idx in 0u32..163840 {
        let mut w = [0u64; 64];
        for j in 0..16u32 {
            w[j as usize] = (block_idx * 16 + j) as u64;
        }

        syscall_sha256_extend(&mut w);
        syscall_sha256_compress(&mut w, &mut state);
    }

    println!("sha256 hash: {:?}", state);
}
