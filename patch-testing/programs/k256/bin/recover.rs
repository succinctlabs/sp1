#![no_main]
sp1_zkvm::entrypoint!(main);

use k256::ecdsa::{
    SigningKey, VerifyingKey,
};
use rand_core::OsRng; 
use hex_literal::hex;

fn main() {
    let message = hex!("656432353531392d636f6e73656e7375732074657374206d657373616765");

    let signing_key = SigningKey::random(&mut OsRng);
    let (sig, recid) = signing_key.sign_prehash_recoverable(&message).unwrap();

    // pass in the wrong message
    let recovered = VerifyingKey::recover_from_prehash(&message, &sig, recid).unwrap();
    
    assert_eq!(signing_key.verifying_key(), &recovered);
}
