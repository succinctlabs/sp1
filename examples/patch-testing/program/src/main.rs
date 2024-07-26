#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::{address, hex};
use curve25519_dalek_ng::edwards::CompressedEdwardsY;
use ed25519_consensus::{Signature, VerificationKey};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, Secp256k1,
};
use sha2_v0_10_6::{Digest as Digest_10_6, Sha256 as Sha256_10_6};
// use sha2_v0_10_8::{Digest as Digest_10_8, Sha256 as Sha256_10_8};
use sha2_v0_9_8::{Digest as Digest_9_8, Sha256 as Sha256_9_8};
use tiny_keccak::{Hasher, Keccak};

/// Simple interface to the [`keccak256`] hash function.
///
/// [`keccak256`]: https://en.wikipedia.org/wiki/SHA-3
fn keccak256<T: AsRef<[u8]>>(bytes: T) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes.as_ref());
    hasher.finalize(&mut output);
    output
}

/// Verify that the patch on recover_ecdsa on secp256k1 correctly patches the ecrecover function.
fn test_secp256k1_patch() {
    // Sourced from ecrecover test: https://github.com/paradigmxyz/reth/blob/18ebc5eaee307dcc1f09c097426770f6dfc3c206/crates/primitives/src/transaction/util.rs#L56
    let vrfy = Secp256k1::verification_only();
    let sig = hex!("650acf9d3f5f0a2c799776a1254355d5f4061762a237396a99a0e0e3fc2bcd6729514a0dacb2e623ac4abd157cb18163ff942280db4d5caad66ddf941ba12e0300");
    let hash = hex!("47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad");
    let out = address!("c08b5542d177ac6686946920409741463a15dddb");
    let rec_id = RecoveryId::from_i32(sig[64] as i32).unwrap();
    let recoverable_sig = RecoverableSignature::from_compact(&sig[..64], rec_id).unwrap();
    let public = vrfy
        .recover_ecdsa(&Message::from_digest(hash), &recoverable_sig)
        .unwrap();
    let eth_address = keccak256(&public.serialize_uncompressed()[1..]);
    assert_eq!(eth_address[12..], out);
}

/// To add testing for a new patch, add a new case to the function below.
fn main() {
    let input = [1u8; 32];

    let sig: Signature = sp1_zkvm::io::read();
    let vk: VerificationKey = sp1_zkvm::io::read();
    let msg: Vec<u8> = sp1_zkvm::io::read_vec();

    // Test Keccak.
    keccak256(input);

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
    assert_eq!(vk.verify(&sig, &msg[..]), Ok(()));

    // Test secp256k1 patch.
    test_secp256k1_patch();
}
