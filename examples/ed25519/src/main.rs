#![no_main]

extern crate succinct_zkvm;

use ed25519_consensus::{Signature, VerificationKey};
use hex_literal::hex;
use std::hint::black_box;

succinct_zkvm::entrypoint!(main);

pub fn main() {
    println!("cycle-tracker-start: get bytes");
    let pub_bytes = hex!("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");
    let msg_bytes =
        hex!("616263616263616263616263616263616263616263616263616263616263616263616263616263");
    let sig_bytes = hex!("46557EFE96D22D07E104D9D7FAB558FB02F6B13116056E6D7C300D7BB132059907D538EAC68EC7864AA2AC2E23EA7082A04002B0ACDAC2FF8CCAD7E80E64DD00");
    println!("cycle-tracker-end: get bytes");

    println!("cycle-tracker-start: verification key");
    let verifying_key = black_box(VerificationKey::try_from(&pub_bytes[..]).unwrap());
    println!("cycle-tracker-end: verification key");
    println!("cycle-tracker-start: singature");
    let sig1 = black_box(Signature::try_from(&sig_bytes[..]).unwrap());
    println!("cycle-tracker-end: singature");
    assert!(verifying_key
        .verify(&black_box(sig1), &black_box(msg_bytes),)
        .is_ok());

    println!("done");
}
