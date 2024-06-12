#![no_main]
sp1_zkvm::entrypoint!(main);

use core::time::Duration;
use sha2_v0_10_6::{Digest as Digest_10_6, Sha256 as Sha256_10_6};
// use sha2_v0_10_8::{Digest as Digest_10_8, Sha256 as Sha256_10_8};
use sha2_v0_9_8::{Digest as Digest_9_8, Sha256 as Sha256_9_8};
use tiny_keccak::{Hasher, Keccak};

fn main() {
    let num_cases = 5;
    for _ in 0..num_cases {
        let input = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(&input);
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);

        let mut sha256_9_8 = Sha256_9_8::new();
        sha256_9_8.update(input);
        let output_9_8 = sha256_9_8.finalize();

        let mut sha256_10_6 = Sha256_10_6::new();
        sha256_10_6.update(input);
        let output_10_6 = sha256_10_6.finalize();

        // let mut sha256_10_8 = Sha256_10_8::new();
        // sha256_10_8.update(input);
        // let output_10_8 = sha256_10_8.finalize();
    }
}
