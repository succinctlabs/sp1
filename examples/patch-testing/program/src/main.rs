#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::Bytes;
use alloy_primitives::{address, bytes, hex};
use alloy_primitives::{B256, B512};
use curve25519_dalek::edwards::CompressedEdwardsY as CompressedEdwardsY_dalek;
use curve25519_dalek_ng::edwards::CompressedEdwardsY as CompressedEdwardsY_dalek_ng;
use ed25519_consensus::{
    Signature as Ed25519ConsensusSignature, VerificationKey as Ed25519ConsensusVerificationKey,
};
use ed25519_dalek::{
    Signature as Ed25519DalekSignature, Verifier, VerifyingKey as Ed25519DalekVerifyingKey,
};

use sha2_v0_10_6::{Digest as Digest_10_6, Sha256 as Sha256_10_6};
// use sha2_v0_10_8::{Digest as Digest_10_8, Sha256 as Sha256_10_8};
use sha2_v0_9_8::{Digest as Digest_9_8, Sha256 as Sha256_9_8};
use tiny_keccak::{Hasher, Keccak};

use secp256k1::{
    ecdsa::{
        RecoverableSignature as Secp256k1RecoverableSignature, RecoveryId as Secp256k1RecoveryId,
    },
    Message as Secp256k1Message,
};

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
fn test_ed25519_dalek() {
    // Example signature and message.
    let vk = hex!("9194c3ead03f5848111db696fe1196fbbeffc69342d51c7cf5e91c502de91eb4");
    let msg = hex!("656432353531392d636f6e73656e7375732074657374206d657373616765");
    let sig = hex!("69261ea5df799b20fc6eeb49aa79f572c8f1e2ba88b37dff184cc55d4e3653d876419bffcc47e5343cdd5fd78121bb32f1c377a5ed505106ad37f19980218f0d");

    let vk = Ed25519DalekVerifyingKey::from_bytes(&vk).unwrap();
    let sig = Ed25519DalekSignature::from_bytes(&sig);

    println!("cycle-tracker-start: ed25519-dalek verify");
    vk.verify(&msg, &sig).unwrap();
    println!("cycle-tracker-end: ed25519-dalek verify");
}

/// Emits ED_ADD and ED_DECOMPRESS syscalls.
fn test_ed25519_consensus() {
    // Example signature and message.
    let vk = hex!("9194c3ead03f5848111db696fe1196fbbeffc69342d51c7cf5e91c502de91eb4");
    let msg = hex!("656432353531392d636f6e73656e7375732074657374206d657373616765");
    let sig = hex!("69261ea5df799b20fc6eeb49aa79f572c8f1e2ba88b37dff184cc55d4e3653d876419bffcc47e5343cdd5fd78121bb32f1c377a5ed505106ad37f19980218f0d");

    let vk: Ed25519ConsensusVerificationKey = vk.try_into().unwrap();
    let sig: Ed25519ConsensusSignature = sig.into();

    println!("cycle-tracker-start: ed25519-consensus verify");
    vk.verify(&sig, &msg).unwrap();
    println!("cycle-tracker-end: ed25519-consensus verify");
}

/// Emits ED_DECOMPRESS syscall.
fn test_curve25519_dalek_ng() {
    let input = [1u8; 32];
    let y = CompressedEdwardsY_dalek_ng(input);

    println!("cycle-tracker-start: curve25519-dalek-ng decompress");
    let decompressed_key = y.decompress();
    println!("cycle-tracker-end: curve25519-dalek-ng decompress");

    let compressed_key = decompressed_key.unwrap().compress();
    assert_eq!(compressed_key, y);
}

/// Emits ED_DECOMPRESS syscall.
fn test_curve25519_dalek() {
    let input = [1u8; 32];
    let y = CompressedEdwardsY_dalek(input);

    println!("cycle-tracker-start: curve25519-dalek decompress");
    let decompressed_key = y.decompress().unwrap();
    println!("cycle-tracker-end: curve25519-dalek decompress");

    let compressed_key = decompressed_key.compress();
    assert_eq!(compressed_key, y);
}

/// Emits KECCAK_PERMUTE syscalls.
fn test_keccak() {
    let input = [1u8; 32];
    let expected_output = hex!("cebc8882fecbec7fb80d2cf4b312bec018884c2d66667c67a90508214bd8bafc");

    let output = keccak256(input);
    assert_eq!(output, expected_output);
}

/// Emits SHA_COMPRESS and SHA_EXTEND syscalls.
fn test_sha256() {
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

    // Can't have two different sha256 versions for the same major version.
    // let mut sha256_10_8 = Sha256_10_8::new();
    // sha256_10_8.update(input);
    // let output_10_8 = sha256_10_8.finalize();
}

/// Emits SECP256K1_ADD, SECP256K1_DOUBLE, and SECP256K1_DECOMPRESS syscalls.
/// Source: https://github.com/alloy-rs/core/blob/adcf7adfa1f35c56e6331bab85b8c56d32a465f1/crates/primitives/src/signature/sig.rs#L620-L631
fn test_k256_patch() {
    // A valid signature.
    let precompile_input = bytes!("a79c77e94d0cd778e606e61130d9065e718eced9408e63df3a71919d5830d82d000000000000000000000000000000000000000000000000000000000000001cd685e79fb0b7ff849cbc6283dd1174b4a06f2aa556f019169a99396fc052b42e2c0ff35d08662f2685929c20ce8eaab568a404d61cf2aa837f1f431e2aef6211");

    let msg = <&B256>::try_from(&precompile_input[0..32]).unwrap();
    let recid = precompile_input[63] - 27;
    let sig = <&B512>::try_from(&precompile_input[64..128]).unwrap();

    println!("cycle-tracker-start: k256 verify");
    let _: Bytes = revm_precompile::secp256k1::ecrecover(sig, recid, msg)
        .map(|o| o.to_vec().into())
        .unwrap_or_default();
    println!("cycle-tracker-end: k256 verify");

    // Signature by the 0x1 private key. Confirms that multi_scalar_multiplication works as intended.
    let precompile_input = bytes!("15499a876f0d57fdc360c760aec98245eba1902610140c14d5f0c3c0284e28a7000000000000000000000000000000000000000000000000000000000000001c2106219ec2e5ef9f7d5ffb303fac05c4066e66db6d501d2e5b1626f2cc8fbe1c316d4e90b09819db9c261017f18e1b5b105855922ec962fd58e83c943e4c4ba3");

    let msg = <&B256>::try_from(&precompile_input[0..32]).unwrap();
    let recid = precompile_input[63] - 27;
    let sig = <&B512>::try_from(&precompile_input[64..128]).unwrap();

    println!("cycle-tracker-start: k256 verify");
    let recovered_address: Bytes = revm_precompile::secp256k1::ecrecover(sig, recid, msg)
        .map(|o| o.to_vec().into())
        .unwrap_or_default();
    println!("cycle-tracker-end: k256 verify");

    println!("recovered_address: {:?}", recovered_address);

    let _ = address!("ea532f4122fb1152b506b545c67e110d276e3448");
}

/// Emits SECP256K1_ADD, SECP256K1_DOUBLE, and SECP256K1_DECOMPRESS syscalls.
fn test_secp256k1_patch() {
    let secp = secp256k1::Secp256k1::new();
    let recovery_id = Secp256k1RecoveryId::from_i32(1).unwrap();
    let signature = Secp256k1RecoverableSignature::from_compact(
        &hex!("80AEBD912F05D302BA8000A3C5D6E604333AAF34E22CC1BA14BE1737213EAED5040D67D6E9FA5FBDFE6E3457893839631B87A41D90508B7C92991ED7824E962D"),
        recovery_id,
    ).unwrap();
    let message_bytes: [u8; 32] = [
        173, 132, 205, 11, 16, 252, 2, 135, 56, 151, 27, 7, 129, 36, 174, 194, 160, 231, 198, 217,
        134, 163, 129, 190, 11, 56, 111, 50, 190, 232, 135, 175,
    ];
    let message = Secp256k1Message::from_digest_slice(&message_bytes)
        .expect("Message could not be created from bytes");
    let expected = "04e76c446148ca6c558910ee241e7dde6d96a7fe3d5a30c00e65aceabe0af9fd2dd131ee7b5d38edafa79eac5110608be0ce01866c1f1a868596b6d991711699c4";

    println!("cycle-tracker-start: secp256k1 verify");
    let public_key = secp
        .recover_ecdsa(&message, &signature) // Use the new context to call recover
        .expect("could not recover public key");
    println!("cycle-tracker-end: secp256k1 verify");

    let serialized_key = public_key.serialize_uncompressed();

    // Use the message in the recover_ecdsa call
    assert_eq!(hex::encode(serialized_key), expected);
}

/// To add testing for a new patch, add a new case to the function below.
pub fn main() {
    // TODO: Specify which syscalls are linked to each function invocation, iterate
    // over this list that is shared between the program and script.
    test_keccak();
    test_sha256();

    test_curve25519_dalek_ng();
    test_curve25519_dalek();

    test_ed25519_dalek();
    test_ed25519_consensus();

    test_k256_patch();
    test_secp256k1_patch();
}
