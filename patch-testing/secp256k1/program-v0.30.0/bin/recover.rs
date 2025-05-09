#![no_main]
sp1_zkvm::entrypoint!(main);

use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, PublicKey, Secp256k1,
};

pub fn main() {
    let times = sp1_zkvm::io::read::<u8>();

    for _ in 0..times {
        let pubkey = inner_recover();
        sp1_zkvm::io::commit(&pubkey);
    }
}

fn inner_recover() -> Option<PublicKey> {
    let recid: i32 = sp1_zkvm::io::read();
    let msg = sp1_zkvm::io::read_vec();
    let sig: [u8; 64] = sp1_zkvm::io::read_vec().try_into().unwrap();
    let recid = RecoveryId::try_from(recid).unwrap();
    let message = Message::from_digest_slice(&msg).unwrap();
    let sig = RecoverableSignature::from_compact(&sig, recid).unwrap();
    let secp = Secp256k1::new();

    secp.recover_ecdsa(&message, &sig).ok()
}
