#![no_main]
sp1_zkvm::entrypoint!(main);

#[cfg(feature = "v0-29-1")]
extern crate secp256k1_v0_29_1 as secp256k1;

#[cfg(feature = "v0-30-0")]
extern crate secp256k1_v0_30_0 as secp256k1;

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

    #[cfg(feature = "v0-29-1")]
    let recid = RecoveryId::from_i32(recid).unwrap();

    #[cfg(feature = "v0-30-0")]
    let recid = RecoveryId::try_from(recid).unwrap();

    let message = Message::from_digest_slice(&msg).unwrap();
    let sig = RecoverableSignature::from_compact(&sig, recid).unwrap();

    let secp = Secp256k1::new();
    #[cfg(feature = "v0-29-1")]
    let recovered = secp.recover_ecdsa(&message, &sig);

    #[cfg(feature = "v0-30-0")]
    let recovered = secp.recover_ecdsa(message, &sig);

    recovered.ok()
}
