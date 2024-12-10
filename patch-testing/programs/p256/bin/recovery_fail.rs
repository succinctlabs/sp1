#![no_main]
sp1_zkvm::entrypoint!(main);

use ecdsa_core::RecoveryId;
use hex_literal::hex;
use p256::{
    ecdsa::{SigningKey, VerifyingKey as P256VerifyingKey},
    elliptic_curve::rand_core::OsRng,
};

pub fn main() {
    let message = hex!("656432353531392d636f6e73656e7375732074657374206d657373616765");

    let signing_key = SigningKey::random(&mut OsRng);
    let (signature, recid) = signing_key.sign_prehash_recoverable(&message).unwrap();

    let (signature, recid) = signature
        .normalize_s()
        .map(|s| {
            let b = recid.to_byte();

            (s, RecoveryId::from_byte(b ^ 1).unwrap())
        })
        .unwrap_or((signature, recid));

    println!("cycle-tracker-start: p256 recovery");
    // pass in the wrong message 
    let recovered_key =
        P256VerifyingKey::recover_from_prehash(&[], &signature, recid);

    assert!(recovered_key.is_err());
}
