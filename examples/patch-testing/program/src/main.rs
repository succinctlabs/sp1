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
use secp256k1::{
    ecdsa::{
        RecoverableSignature as Secp256k1RecoverableSignature, RecoveryId as Secp256k1RecoveryId,
        Signature as Secp256k1Signature,
    },
    Message as Secp256k1Message,
};
use sha2_v0_9_8::{Digest as Digest_9_8, Sha256 as Sha256_9_8};
use tiny_keccak::{Hasher, Keccak};

fn keccak256<T: AsRef<[u8]>>(bytes: T) -> Result<[u8; 32], &'static str> {
    if bytes.as_ref().is_empty() {
        return Err("Input is empty");
    }
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes.as_ref());
    hasher.finalize(&mut output);
    Ok(output)
}

fn test_ed25519_dalek() {
    let vk = hex!("9194c3ead03f5848111db696fe1196fbbeffc69342d51c7cf5e91c502de91eb4");
    let msg = hex!("656432353531392d636f6e73656e7375732074657374206d657373616765");
    let sig = hex!("69261ea5df799b20fc6eeb49aa79f572c8f1e2ba88b37dff184cc55d4e3653d876419bffcc47e5343cdd5fd78121bb32f1c377a5ed505106ad37f19980218f0d");

    if vk.is_empty() || sig.is_empty() {
        println!("Invalid input: Empty verification key or signature");
        return;
    }

    let vk = Ed25519DalekVerifyingKey::from_bytes(&vk).unwrap();
    let sig = Ed25519DalekSignature::from_bytes(&sig);

    println!("cycle-tracker-start: ed25519-dalek verify");
    vk.verify(&msg, &sig).unwrap();
    println!("cycle-tracker-end: ed25519-dalek verify");
}

fn test_ed25519_consensus() {
    let vk = hex!("9194c3ead03f5848111db696fe1196fbbeffc69342d51c7cf5e91c502de91eb4");
    let msg = hex!("656432353531392d636f6e73656e7375732074657374206d657373616765");
    let sig = hex!("69261ea5df799b20fc6eeb49aa79f572c8f1e2ba88b37dff184cc55d4e3653d876419bffcc47e5343cdd5fd78121bb32f1c377a5ed505106ad37f19980218f0d");

    if vk.is_empty() || sig.is_empty() {
        println!("Invalid input: Empty verification key or signature");
        return;
    }

    let vk: Ed25519ConsensusVerificationKey = vk.try_into().unwrap();
    let sig: Ed25519ConsensusSignature = sig.into();

    println!("cycle-tracker-start: ed25519-consensus verify");
    vk.verify(&sig, &msg).unwrap();
    println!("cycle-tracker-end: ed25519-consensus verify");
}

fn test_curve25519_dalek_ng() {
    let input = [1u8; 32];
    let y = CompressedEdwardsY_dalek_ng(input);

    println!("cycle-tracker-start: curve25519-dalek-ng decompress");
    let decompressed_key = y.decompress();
    if decompressed_key.is_none() {
        println!("Error: Decompression failed");
        return;
    }
    println!("cycle-tracker-end: curve25519-dalek-ng decompress");

    let compressed_key = decompressed_key.unwrap().compress();
    assert_eq!(compressed_key, y);
}

fn test_curve25519_dalek() {
    let input = [1u8; 32];
    let y = CompressedEdwardsY_dalek(input);

    println!("cycle-tracker-start: curve25519-dalek decompress");
    let decompressed_key = y.decompress().unwrap();
    println!("cycle-tracker-end: curve25519-dalek decompress");

    let compressed_key = decompressed_key.compress();
    assert_eq!(compressed_key, y);
}

fn test_keccak() {
    let input = [1u8; 32];
    let expected_output = hex!("cebc8882fecbec7fb80d2cf4b312bec018884c2d66667c67a90508214bd8bafc");

    match keccak256(input) {
        Ok(output) => assert_eq!(output, expected_output),
        Err(e) => println!("Keccak256 error: {}", e),
    }
}

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
}

fn test_p256_patch() {
    let precompile_input = bytes!("b5a77e7a90aa14e0bf5f337f06f597148676424fae26e175c6e5621c34351955289f319789da424845c9eac935245fcddd805950e2f02506d09be7e411199556d262144475b1fa46ad85250728c600c53dfd10f8b3f4adf140e27241aec3c2da3a81046703fccf468b48b145f939efdbb96c3786db712b3113bb2488ef286cdcef8afe82d200a5bb36b5462166e8ce77f2d831a52ef2135b2af188110beaefb1");

    if precompile_input.is_empty() {
        println!("Invalid input: Empty precompile input");
        return;
    }

    println!("cycle-tracker-start: p256 verify");
    let result = revm_precompile::secp256r1::verify_impl(&precompile_input);
    println!("cycle-tracker-end: p256 verify");

    assert!(result.is_some());
}

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
    let expected = "04e76c446148ca6ccfefea2027fe1748da88d6c8eb6b4a7c35ae0a2d038d7db5f44205619b169fdcd1fc86cfa722c378d97bdbac77fdf1b470b849b205e9fa01bde";

    let recovered_pubkey = signature.recover(&secp, &message).unwrap();

    assert_eq!(recovered_pubkey.to_string(), expected);
}

#[no_mangle]
fn main() {
    test_ed25519_dalek();
    test_ed25519_consensus();
    test_curve25519_dalek();
    test_curve25519_dalek_ng();
    test_keccak();
    test_sha256();
    test_p256_patch();
    test_secp256k1_patch();
}
