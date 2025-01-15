#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2_v0_9_8::{Digest as D1, Sha256 as Sha256_9_8};
use sha2_v0_10_8::{Digest as D2, Sha256 as Sha256_10_8};

/// Emits SHA_COMPRESS and SHA_EXTEND syscalls.
pub fn main() {
    let times = sp1_zkvm::io::read::<usize>();

    for _ in 0..times {
        let preimage = sp1_zkvm::io::read_vec();

        let mut sha256_9_8 = Sha256_9_8::new();
        sha256_9_8.update(&preimage);

        let mut sha256_10_6 = Sha256_10_8::new();
        sha256_10_6.update(&preimage);

        let output_9_8: [u8; 32] = sha256_9_8.finalize().into();
        let output_10_6: [u8; 32] = sha256_10_6.finalize().into();

        sp1_zkvm::io::commit(&(output_9_8, output_10_6));
    }
}
