#![no_main]
sp1_zkvm::entrypoint!(main);

use ecdsa_core::signature::Verifier;
use k256::schnorr::{Signature, VerifyingKey};

pub fn main() {
    let times = sp1_zkvm::io::read::<u8>();

    for _ in 0..times {
        sp1_zkvm::io::commit(&inner());
    }
}

fn inner() -> bool {
    let message: [u8; 32] = sp1_zkvm::io::read();
    let signature = sp1_zkvm::io::read_vec();
    let vkey_bytes = sp1_zkvm::io::read_vec();
    let vkey = VerifyingKey::from_bytes(vkey_bytes.as_slice()).unwrap();
    let signature = Signature::try_from(signature.as_slice()).unwrap();

    vkey.verify(&message, &signature).is_ok()
}
