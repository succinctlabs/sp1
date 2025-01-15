#![no_main]
sp1_zkvm::entrypoint!(main);

use rsa::{
    pkcs1v15::{Signature, VerifyingKey},
    sha2::Sha256,
    signature::Verifier,
    RsaPublicKey,
};

pub fn main() {
    let times: u8 = sp1_zkvm::io::read();

    for _ in 0..times {
        verify_inner();
    }
}

fn verify_inner() {
    let signature_bytes: Vec<u8> = sp1_zkvm::io::read();
    let signature: Signature = signature_bytes.as_slice().try_into().unwrap();
    let pubkey: RsaPublicKey = sp1_zkvm::io::read();
    let data: Vec<u8> = sp1_zkvm::io::read();
    
    let vkey = VerifyingKey::<Sha256>::new(pubkey);

    assert!(vkey.verify(&data, &signature).is_ok());

}
