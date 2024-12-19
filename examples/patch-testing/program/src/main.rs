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
use secp256k1::{
    ecdsa::{
        RecoverableSignature as Secp256k1RecoverableSignature, RecoveryId as Secp256k1RecoveryId,
        Signature as Secp256k1Signature,
    },
    Message as Secp256k1Message,
};
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
    let input_passing = [1u8; 32];

    // This y-coordinate is not square, and therefore not on the curve
    let limbs: [u64; 4] =
        [8083970408152925034, 11907700107021980321, 16259949789167878387, 5645861033211660086];

    // convert to bytes
    let input_failing: [u8; 32] =
        limbs.iter().flat_map(|l| l.to_be_bytes()).collect::<Vec<u8>>().try_into().unwrap();

    let y_passing = CompressedEdwardsY_dalek(input_passing);

    println!("cycle-tracker-start: curve25519-dalek decompress");
    let decompressed_key = y_passing.decompress().unwrap();
    println!("cycle-tracker-end: curve25519-dalek decompress");

    let compressed_key = decompressed_key.compress();
    assert_eq!(compressed_key, y_passing);

    let y_failing = CompressedEdwardsY_dalek(input_failing);
    println!("cycle-tracker-start: curve25519-dalek decompress");
    let decompressed_key = y_failing.decompress();
    println!("cycle-tracker-end: curve25519-dalek decompress");

    assert!(decompressed_key.is_none());
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

fn test_p256_patch() {
    // A valid signature.
    let precompile_input = bytes!("b5a77e7a90aa14e0bf5f337f06f597148676424fae26e175c6e5621c34351955289f319789da424845c9eac935245fcddd805950e2f02506d09be7e411199556d262144475b1fa46ad85250728c600c53dfd10f8b3f4adf140e27241aec3c2da3a81046703fccf468b48b145f939efdbb96c3786db712b3113bb2488ef286cdcef8afe82d200a5bb36b5462166e8ce77f2d831a52ef2135b2af188110beaefb1");
    println!("cycle-tracker-start: p256 verify");
    let result = revm_precompile::secp256r1::verify_impl(&precompile_input);
    println!("cycle-tracker-end: p256 verify");

    assert!(result.is_some());

    let invalid_test_cases = vec![
            bytes!("3cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4da73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d604aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff37618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e"),
            bytes!("afec5769b5cf4e310a7d150508e82fb8e3eda1c2c94c61492d3bd8aea99e06c9e22466e928fdccef0de49e3503d2657d00494a00e764fd437bdafa05f5922b1fbbb77c6817ccf50748419477e843d5bac67e6a70e97dde5a57e0c983b777e1ad31a80482dadf89de6302b1988c82c29544c9c07bb910596158f6062517eb089a2f54c9a0f348752950094d3228d3b940258c75fe2a413cb70baa21dc2e352fc5"),
            bytes!("f775723953ead4a90411a02908fd1a629db584bc600664c609061f221ef6bf7c440066c8626b49daaa7bf2bcc0b74be4f7a1e3dcf0e869f1542fe821498cbf2de73ad398194129f635de4424a07ca715838aefe8fe69d1a391cfa70470795a80dd056866e6e1125aff94413921880c437c9e2570a28ced7267c8beef7e9b2d8d1547d76dfcf4bee592f5fefe10ddfb6aeb0991c5b9dbbee6ec80d11b17c0eb1a"),
            bytes!("4cee90eb86eaa050036147a12d49004b6a"),
            bytes!("4cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4da73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d604aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff37618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e00"),
            bytes!("b5a77e7a90aa14e0bf5f337f06f597148676424fae26e175c6e5621c34351955289f319789da424845c9eac935245fcddd805950e2f02506d09be7e411199556d262144475b1fa46ad85250728c600c53dfd10f8b3f4adf140e27241aec3c2daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaef8afe82d200a5bb36b5462166e8ce77f2d831a52ef2135b2af188110beaefb1")
    ];

    for input in invalid_test_cases {
        println!("cycle-tracker-start: p256 verify false");
        let result = revm_precompile::secp256r1::verify_impl(&input);
        println!("cycle-tracker-end: p256 verify false");
        assert!(result.is_none());
    }
}

/// Emits SECP256K1_ADD, SECP256K1_DOUBLE, and SECP256K1_DECOMPRESS syscalls.
/// Source: https://github.com/alloy-rs/core/blob/adcf7adfa1f35c56e6331bab85b8c56d32a465f1/crates/primitives/src/signature/sig.rs#L620-L631
fn test_k256_patch() {
    // A valid signature.
    let precompile_input = bytes!("a79c77e94d0cd778e606e61130d9065e718eced9408e63df3a71919d5830d82d000000000000000000000000000000000000000000000000000000000000001cd685e79fb0b7ff849cbc6283dd1174b4a06f2aa556f019169a99396fc052b42e2c0ff35d08662f2685929c20ce8eaab568a404d61cf2aa837f1f431e2aef6211");

    let msg = <&B256>::try_from(&precompile_input[0..32]).unwrap();
    let recid = precompile_input[63] - 27;
    println!("recid: {}", recid);
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

    let sig = Secp256k1Signature::from_compact(&hex!("80AEBD912F05D302BA8000A3C5D6E604333AAF34E22CC1BA14BE1737213EAED5040D67D6E9FA5FBDFE6E3457893839631B87A41D90508B7C92991ED7824E962D")).unwrap();
    println!("cycle-tracker-start: secp256k1 verify_ecdsa");
    let result = secp.verify_ecdsa(&message, &sig, &public_key);
    println!("cycle-tracker-end: secp256k1 verify_ecdsa");

    assert!(result.is_ok());

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
    test_p256_patch();
}
