#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2_v0_9_8::{Digest as D1, Sha256 as Sha256_9_8};
use sha2_v0_10_6::{Digest as D2, Sha256 as Sha256_10_6};
use hex_literal::hex;

/// Emits SHA_COMPRESS and SHA_EXTEND syscalls.
pub fn main() {
    let input = [1u8; 32];
    let expected_output = hex!("72cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9d521f015363793");

    let mut sha256_9_8 = Sha256_9_8::new();
    sha256_9_8.update(input);
    let output_9_8: [u8; 32] = sha256_9_8.finalize().into();
    assert_eq!(output_9_8, expected_output);

    let mut sha256_10_6 = Sha256_10_6::new();
    sha256_10_6.update(input);
    let output_10_6: [u8; 32] = sha256_10_6.finalize().into();
    assert_eq!(output_10_6, expected_output);
}
