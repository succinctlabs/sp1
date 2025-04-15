#![no_main]
sp1_zkvm::entrypoint!(main);

#[cfg(feature = "v0-9-9")]
extern crate sha2_v0_9_9 as sha2;

#[cfg(feature = "v0-10-6")]
extern crate sha2_v0_10_6 as sha2;

#[cfg(feature = "v0-10-8")]
extern crate sha2_v0_10_8 as sha2;

use sha2::{Digest, Sha256};

/// Emits SHA_COMPRESS and SHA_EXTEND syscalls.
pub fn main() {
    let times = sp1_zkvm::io::read::<usize>();

    for _ in 0..times {
        let preimage = sp1_zkvm::io::read_vec();

        let mut sha256 = Sha256::new();
        sha256.update(&preimage);

        let output: [u8; 32] = sha256.finalize().into();

        sp1_zkvm::io::commit(&output);
    }
}
