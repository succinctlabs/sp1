#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let times = sp1_zkvm::io::read::<u8>();

    for _ in 0..times {
        let recid: i32 = sp1_zkvm::io::read();
        let msg = sp1_zkvm::io::read_vec();
        let sig: [u8; 64] = sp1_zkvm::io::read_vec().try_into().unwrap();

        let pubkey_v0_29_1 = inner_recover_v0_29_1(recid, &msg, &sig);
        let pubkey_v0_30_0 = inner_recover_v0_30_0(recid, &msg, &sig);
        sp1_zkvm::io::commit(&(pubkey_v0_29_1, pubkey_v0_30_0));
    }
}

fn inner_recover_v0_29_1(
    recid: i32,
    msg: &[u8],
    sig: &[u8],
) -> Option<secp256k1_v0_29_1::PublicKey> {
    use secp256k1_v0_29_1::{
        ecdsa::{RecoverableSignature, RecoveryId},
        Message, Secp256k1,
    };

    let recid = RecoveryId::from_i32(recid).unwrap();
    let message = Message::from_digest_slice(msg).unwrap();
    let sig = RecoverableSignature::from_compact(sig, recid).unwrap();
    let secp = Secp256k1::new();
    let recovered = secp.recover_ecdsa(&message, &sig);

    recovered.ok()
}

fn inner_recover_v0_30_0(
    recid: i32,
    msg: &[u8],
    sig: &[u8],
) -> Option<secp256k1_v0_30_0::PublicKey> {
    use secp256k1_v0_30_0::{
        ecdsa::{RecoverableSignature, RecoveryId},
        Message, Secp256k1,
    };

    let recid = RecoveryId::try_from(recid).unwrap();
    let message = Message::from_digest_slice(msg).unwrap();
    let sig = RecoverableSignature::from_compact(sig, recid).unwrap();
    let secp = Secp256k1::new();
    let recovered = secp.recover_ecdsa(message, &sig);

    recovered.ok()
}
