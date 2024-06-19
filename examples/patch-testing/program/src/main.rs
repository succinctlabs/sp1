#![no_main]
sp1_zkvm::entrypoint!(main);

use curve25519_dalek_ng::edwards::CompressedEdwardsY;
use ed25519_consensus::{Signature, VerificationKey};
use sha2_v0_10_6::{Digest as Digest_10_6, Sha256 as Sha256_10_6};
// use sha2_v0_10_8::{Digest as Digest_10_8, Sha256 as Sha256_10_8};
use sha2_v0_9_8::{Digest as Digest_9_8, Sha256 as Sha256_9_8};
use tiny_keccak::{Hasher, Keccak};

/// To add testing for a new patch, add a new case to the function below.
fn main() {
    let input = [1u8; 32];

    let sig: Signature = sp1_zkvm::io::read();
    let vk: VerificationKey = sp1_zkvm::io::read();
    let msg: Vec<u8> = sp1_zkvm::io::read_vec();

    // Test Keccak.
    let mut hasher = Keccak::v256();
    hasher.update(&input);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);

    // Test SHA256.
    let mut sha256_9_8 = Sha256_9_8::new();
    sha256_9_8.update(input);
    let _ = sha256_9_8.finalize();

    let mut sha256_10_6 = Sha256_10_6::new();
    sha256_10_6.update(input);
    let _ = sha256_10_6.finalize();

    // let mut sha256_10_8 = Sha256_10_8::new();
    // sha256_10_8.update(input);
    // let output_10_8 = sha256_10_8.finalize();

    // Test curve25519-dalek-ng.
    let y = CompressedEdwardsY(input);
    let _ = y.decompress();

    // Test ed25519-consensus.
    assert_eq!(vk.verify(&sig, &msg[..]), Ok(()))
}
