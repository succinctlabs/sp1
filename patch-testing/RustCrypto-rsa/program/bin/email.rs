#![no_main]
sp1_zkvm::entrypoint!(main);

use rsa::{
    pkcs1v15,
    pkcs8::DecodePrivateKey,
    sha2::Sha256,
    signature::{Keypair, Signer, Verifier},
    RsaPrivateKey,
};

pub fn main() {
    let private_key_string: String = sp1_zkvm::io::read();
    let email_string: String = sp1_zkvm::io::read();

    let private_key = RsaPrivateKey::from_pkcs8_pem(&private_key_string).unwrap();
    let signing_key = pkcs1v15::SigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign(email_string.as_bytes());
    let verifying_key = signing_key.verifying_key();

    verifying_key.verify(email_string.as_bytes(), &signature).unwrap()
}
