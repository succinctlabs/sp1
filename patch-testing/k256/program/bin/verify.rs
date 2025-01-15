#![no_main]
sp1_zkvm::entrypoint!(main);

use ecdsa_core::signature::Verifier;
use k256::ecdsa::{Signature, VerifyingKey};

pub fn main() {
    let times = sp1_zkvm::io::read::<u8>();

    for _ in 0..times {
        sp1_zkvm::io::commit(&inner());
    }
}

fn inner() -> bool {
    let (message, signature, vkey_bytes): (Vec<u8>, Signature, Vec<u8>) = sp1_zkvm::io::read();
    let vkey = VerifyingKey::from_sec1_bytes(&vkey_bytes).unwrap();

    vkey.verify(&message, &signature).is_ok()
}
