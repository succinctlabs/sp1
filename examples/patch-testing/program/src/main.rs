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

/// Emits SECP256K1_ADD, SECP256K1_DOUBLE, and SECP256K1_DECOMPRESS syscalls.
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

/// Emits ED_ADD and ED_DECOMPRESS syscalls.
fn test_ed25519_consensus() {
    // Example from ed25519-consensus docs.
    let vk = hex!("9194c3ead03f5848111db696fe1196fbbeffc69342d51c7cf5e91c502de91eb4");
    let msg = hex!("656432353531392d636f6e73656e7375732074657374206d657373616765");
    let sig = hex!("69261ea5df799b20fc6eeb49aa79f572c8f1e2ba88b37dff184cc55d4e3653d876419bffcc47e5343cdd5fd78121bb32f1c377a5ed505106ad37f19980218f0d");

    let vk: VerificationKey = vk.try_into().unwrap();
    let sig: Signature = sig.into();
    vk.verify(&sig, &msg).unwrap();
}

/// Emits ED_DECOMPRESS syscalls.
fn test_curve25519_dalek_ng() {
    let input = [1u8; 32];
    let y = CompressedEdwardsY(input);
    let _ = y.decompress();
}

/// Emits KECCAK_PERMUTE syscalls.
fn test_keccak() {
    let input = [1u8; 32];
    let _ = keccak256(input);
}

/// Emits SHA_COMPRESS and SHA_EXTEND syscalls.
fn test_sha256() {
    let input = [1u8; 32];
    let mut sha256_9_8 = Sha256_9_8::new();
    sha256_9_8.update(input);
    let _ = sha256_9_8.finalize();

    let mut sha256_10_6 = Sha256_10_6::new();
    sha256_10_6.update(input);
    let _ = sha256_10_6.finalize();

    // Can't have two different sha256 versions for the same major version.
    // let mut sha256_10_8 = Sha256_10_8::new();
    // sha256_10_8.update(input);
    // let output_10_8 = sha256_10_8.finalize();
}

/// To add testing for a new patch, add a new case to the function below.
fn main() {
    // TODO: Specify which syscalls are linked to each function invocation, iterate
    // over this list that is shared between the program and script.
    test_keccak();
    test_sha256();
    test_curve25519_dalek_ng();
    test_ed25519_consensus();
    test_secp256k1_patch();
}
