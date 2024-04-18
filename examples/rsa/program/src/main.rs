#![no_main]
sp1_zkvm::entrypoint!(main);

use rsa::PaddingScheme;
use rsa::PublicKey;
use rsa::{pkcs8::DecodePublicKey, RsaPublicKey};
use sha2::Digest;
use sha2::Sha256;

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    let pk_der = sp1_zkvm::io::read::<Vec<u8>>();
    let message = sp1_zkvm::io::read::<Vec<u8>>();
    let signature = sp1_zkvm::io::read::<Vec<u8>>();

    let public_key = RsaPublicKey::from_public_key_der(&pk_der).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(message);
    let hashed_msg = hasher.finalize();

    let padding = PaddingScheme::new_pkcs1v15_sign(Some(rsa::hash::Hash::SHA2_256));
    let verification = public_key.verify(padding, &hashed_msg, &signature);

    let verified = match verification {
        Ok(_) => {
            println!("Signature verified successfully.");
            true
        }
        Err(e) => {
            println!("Failed to verify signature: {:?}", e);
            false
        }
    };

    // Write the output of the program.
    //
    // Behind the scenes, this also compiles down to a custom system call which handles writing
    sp1_zkvm::io::commit(&verified);
}
