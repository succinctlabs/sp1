#![no_main]
sp1_zkvm::entrypoint!(main);

use hex_literal::hex;
use p256::{
    ecdsa::{SigningKey,signature::Verifier},
    elliptic_curve::rand_core::OsRng,
};

pub fn main() {
    let message = hex!("656432353531392d636f6e73656e7375732074657374206d657373616765");

    let signing_key = SigningKey::random(&mut OsRng);
    let (signature, _) = signing_key.sign_recoverable(&message).unwrap();

    let signature = signature.normalize_s().unwrap_or(signature);
   
    signing_key.verifying_key().verify(&message, &signature).unwrap();
}
