#![no_main]
sp1_zkvm::entrypoint!(main);

use ed25519_dalek::*;
use hex_literal::hex;
use std::hint::black_box;

pub fn main() {
    let pub_bytes = hex!("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");
    let msg_bytes =
        hex!("616263616263616263616263616263616263616263616263616263616263616263616263616263");
    let sig_bytes = hex!("46557EFE96D22D07E104D9D7FAB558FB02F6B13116056E6D7C300D7BB132059907D538EAC68EC7864AA2AC2E23EA7082A04002B0ACDAC2FF8CCAD7E80E64DD00");
    let verifying_key = black_box(VerifyingKey::from_bytes(&pub_bytes).unwrap());
    let sig1 = black_box(Signature::try_from(&sig_bytes[..]).unwrap());
    assert!(verifying_key.verify_strict(&black_box(msg_bytes), &black_box(sig1)).is_ok());
    println!("done");
}
