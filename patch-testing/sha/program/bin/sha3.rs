#![no_main]
sp1_zkvm::entrypoint!(main);

#[cfg(feature = "sha3-v0-10-8")]
extern crate sha3_v0_10_8 as sha3;

#[cfg(feature = "sha3-v0-11-0")]
extern crate sha3_v0_11_0 as sha3;

use sha3::{Digest, Sha3_256};

/// Emits KECCAK_PERMUTE syscalls.
pub fn main() {
    let times = sp1_zkvm::io::read::<usize>();

    for _ in 0..times {
        let preimage = sp1_zkvm::io::read_vec();

        let mut sha3 = Sha3_256::new();

        sha3.update(&preimage);

        let digest: [u8; 32] = sha3.finalize().into();

        sp1_zkvm::io::commit(&digest);
    }
}
