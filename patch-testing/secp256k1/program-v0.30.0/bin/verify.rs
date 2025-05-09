#![no_main]
sp1_zkvm::entrypoint!(main);

use secp256k1::{ecdsa::Signature, Message, PublicKey};

pub fn main() {
    let times = sp1_zkvm::io::read::<u8>();

    for i in 0..times {
        println!("{}", i);
        sp1_zkvm::io::commit(&inner_verify());
    }
}

fn inner_verify() -> bool {
    let msg_digest = sp1_zkvm::io::read_vec();
    let signature = sp1_zkvm::io::read_vec();
    let message = Message::from_digest_slice(&msg_digest).unwrap();
    let signature = Signature::from_der(&signature).unwrap();
    let pubkey = sp1_zkvm::io::read::<PublicKey>();
    let secp = secp256k1::Secp256k1::new();

    secp.verify_ecdsa(&message, &signature, &pubkey).is_ok()
}
