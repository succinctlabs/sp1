#![no_main]

extern crate succinct_zkvm;

use ed25519_dalek::*;
use hex_literal::hex;
use std::hint::black_box;

succinct_zkvm::entrypoint!(main);

pub fn main() {
    let pub_bytes = hex!("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");
    let msg_bytes =
        hex!("616263616263616263616263616263616263616263616263616263616263616263616263616263");
    let sig_bytes = hex!("46557EFE96D22D07E104D9D7FAB558FB02F6B13116056E6D7C300D7BB132059907D538EAC68EC7864AA2AC2E23EA7082A04002B0ACDAC2FF8CCAD7E80E64DD00");

    let verifying_key = black_box(VerifyingKey::from_bytes(&pub_bytes).unwrap());
    let sig1 = black_box(Signature::try_from(&sig_bytes[..]).unwrap());
    assert!(verifying_key
        .verify_strict(&black_box(msg_bytes), &black_box(sig1))
        .is_ok());

    // let sec_bytes = hex!("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");
    // let signing_key = SigningKey::from_bytes(&sec_bytes);
    // assert_eq!(verifying_key, signing_key.verifying_key());
    // let sig2: Signature = signing_key.sign(&msg_bytes);
    // println!("sig: {}", sig2);

    println!("done");
}
