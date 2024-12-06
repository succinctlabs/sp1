#![no_main]
sp1_zkvm::entrypoint!(main);

use hex_literal::hex;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

pub fn main() {
    let message = hex!("656432353531392d636f6e73656e7375732074657374206d657373616765");

    let signature = Signature::from_slice(&[
        140, 186, 254, 111, 141, 150, 104, 212, 189, 227, 227, 89, 133, 106, 209, 230, 213, 212,
        178, 5, 172, 148, 101, 213, 246, 205, 15, 251, 234, 157, 124, 236, 156, 241, 147, 55, 234,
        205, 76, 131, 221, 234, 209, 116, 89, 200, 81, 119, 104, 185, 218, 8, 179, 138, 222, 210,
        81, 139, 5, 21, 92, 35, 78, 131,
    ])
    .unwrap();

    let vkey = VerifyingKey::from_sec1_bytes(&[
        4, 160, 3, 79, 7, 54, 42, 61, 116, 71, 105, 95, 67, 188, 131, 164, 194, 47, 112, 70, 145,
        75, 113, 173, 227, 173, 32, 126, 230, 225, 73, 12, 63, 54, 217, 219, 1, 126, 220, 198, 92,
        101, 31, 230, 13, 160, 201, 227, 217, 58, 19, 76, 67, 16, 71, 157, 11, 150, 159, 127, 239,
        40, 7, 62, 191,
    ])
    .unwrap();

    if signature.normalize_s().is_none() {
        panic!("We have a low sig");
    }

    vkey.verify(&message, &signature).unwrap();
}
