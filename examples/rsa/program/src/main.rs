#![no_main]
sp1_zkvm::entrypoint!(main);

use rsa::Pkcs1v15Sign;
use rsa::{pkcs8::DecodePublicKey, RsaPublicKey};
use sha2::{Digest, Sha256}; // Ensure this is imported for the Digest trait to work

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a system call which handles reading inputs
    let pk_der = sp1_zkvm::io::read::<Vec<u8>>();
    let message = sp1_zkvm::io::read::<Vec<u8>>();
    let signature = sp1_zkvm::io::read::<Vec<u8>>();

    let public_key = RsaPublicKey::from_public_key_der(&pk_der).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(message);
    let hashed_msg = hasher.finalize();

    let verification = public_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_msg, &signature);

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
    // Behind the scenes, this also compiles down to a system call which handles writing
    sp1_zkvm::io::commit(&verified);
}
