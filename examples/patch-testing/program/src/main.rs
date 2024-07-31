#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::{address, hex, Signature};
use curve25519_dalek_ng::edwards::CompressedEdwardsY;
use ed25519_consensus::{Signature as Ed25519Signature, VerificationKey as Ed25519VerificationKey};
// use k256::ecdsa::{RecoveryId, Signature as K256Signature};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, PublicKey, SECP256K1,
};
use sha2_v0_10_6::{Digest as Digest_10_6, Sha256 as Sha256_10_6};
// use sha2_v0_10_8::{Digest as Digest_10_8, Sha256 as Sha256_10_8};
use sha2_v0_9_8::{Digest as Digest_9_8, Sha256 as Sha256_9_8};
use std::str::FromStr;
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

/// Emits ED_ADD and ED_DECOMPRESS syscalls.
fn test_ed25519_consensus() {
    // Example signature and message.
    let vk = hex!("9194c3ead03f5848111db696fe1196fbbeffc69342d51c7cf5e91c502de91eb4");
    let msg = hex!("656432353531392d636f6e73656e7375732074657374206d657373616765");
    let sig = hex!("69261ea5df799b20fc6eeb49aa79f572c8f1e2ba88b37dff184cc55d4e3653d876419bffcc47e5343cdd5fd78121bb32f1c377a5ed505106ad37f19980218f0d");

    let vk: Ed25519VerificationKey = vk.try_into().unwrap();
    let sig: Ed25519Signature = sig.into();
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

/// Emits SECP256K1_ADD, SECP256K1_DOUBLE, and SECP256K1_DECOMPRESS syscalls.
/// Source: https://github.com/alloy-rs/core/blob/adcf7adfa1f35c56e6331bab85b8c56d32a465f1/crates/primitives/src/signature/sig.rs#L620-L631
fn test_k256_patch() {
    let sig = Signature::from_str(
        "b91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c"
    ).expect("could not parse signature");
    let expected = address!("2c7536E3605D9C16a7a3D7b1898e529396a65c23");

    assert_eq!(
        sig.recover_address_from_msg("Some data")
            .expect("could not recover address"),
        expected
    );
}

fn test_secp256k1_patch() {
    let secp = secp256k1::Secp256k1::new();
    let recovery_id = RecoveryId::from_i32(1).unwrap();
    let signature = RecoverableSignature::from_compact(
        &hex!("80AEBD912F05D302BA8000A3C5D6E604333AAF34E22CC1BA14BE1737213EAED5040D67D6E9FA5FBDFE6E3457893839631B87A41D90508B7C92991ED7824E962D"),
        recovery_id,
    ).unwrap();
    let message_bytes: [u8; 32] = [
        173, 132, 205, 11, 16, 252, 2, 135, 56, 151, 27, 7, 129, 36, 174, 194, 160, 231, 198, 217,
        134, 163, 129, 190, 11, 56, 111, 50, 190, 232, 135, 175,
    ];
    let message =
        Message::from_slice(&message_bytes).expect("Message could not be created from bytes");
    let expected = "04e76c446148ca6c558910ee241e7dde6d96a7fe3d5a30c00e65aceabe0af9fd2dd131ee7b5d38edafa79eac5110608be0ce01866c1f1a868596b6d991711699c4";
    let public_key = secp
        .recover_ecdsa(&message, &signature) // Use the new context to call recover
        .expect("could not recover public key")
        .serialize_uncompressed();

    // Use the message in the recover_ecdsa call
    assert_eq!(hex::encode(public_key), expected);
}

/// To add testing for a new patch, add a new case to the function below.
fn main() {
    // TODO: Specify which syscalls are linked to each function invocation, iterate
    // over this list that is shared between the program and script.
    println!("cycle-tracker-start: keccak");
    test_keccak();
    println!("cycle-tracker-end: keccak");

    println!("cycle-tracker-start: sha256");
    test_sha256();
    println!("cycle-tracker-end: sha256");

    println!("cycle-tracker-start: curve25519");
    test_curve25519_dalek_ng();
    println!("cycle-tracker-end: curve25519");

    println!("cycle-tracker-start: ed25519");
    test_ed25519_consensus();
    println!("cycle-tracker-end: ed25519");

    println!("cycle-tracker-start: k256");
    test_k256_patch();
    println!("cycle-tracker-end: k256");

    println!("cycle-tracker-start: secp256k1");
    test_secp256k1_patch();
    println!("cycle-tracker-end: secp256k1");
}
