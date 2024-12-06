#![no_main]
sp1_zkvm::entrypoint!(main);

use ecdsa_core::RecoveryId;
use hex_literal::hex;
use p256::ecdsa::{Signature, VerifyingKey};

pub fn main() {
    let message = hex!("656432353531392d636f6e73656e7375732074657374206d657373616765");

    let signature = Signature::from_slice(&[
        204, 62, 88, 221, 140, 45, 13, 16, 231, 190, 81, 143, 234, 1, 197, 169, 183, 204, 231, 93,
        74, 162, 164, 32, 38, 168, 22, 34, 85, 187, 252, 141, 180, 96, 216, 187, 174, 255, 182,
        238, 101, 246, 39, 3, 139, 243, 93, 80, 36, 35, 251, 104, 182, 54, 193, 238, 249, 22, 144,
        227, 114, 218, 181, 141,
    ])
    .unwrap();

    let recid = RecoveryId::from_byte(0).unwrap();

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

    println!("cycle-tracker-start: p256 recovery");
    let recovered_key = VerifyingKey::recover_from_prehash(&message, &signature, recid).unwrap();

    assert_eq!(&recovered_key, &vkey);
    println!("cycle-tracker-end: p256 recovery");
}
