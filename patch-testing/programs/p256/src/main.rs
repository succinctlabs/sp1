#![no_main]
sp1_zkvm::entrypoint!(main);

use p256::{
    ecdsa::{SigningKey, VerifyingKey as P256VerifyingKey},
    elliptic_curve::rand_core::OsRng,
};
use hex_literal::hex;

pub fn main() {
    let message = hex!("656432353531392d636f6e73656e7375732074657374206d657373616765");

    let signing_key = SigningKey::random(&mut OsRng);
    let (signature, recid) = signing_key.sign_prehash_recoverable(&message).unwrap();

    println!("cycle-tracker-start: p256 recovery");
    let recovered_key =
        P256VerifyingKey::recover_from_prehash(&message, &signature, recid).unwrap();

    assert_eq!(&recovered_key, signing_key.verifying_key());
    println!("cycle-tracker-end: p256 recovery");
}
