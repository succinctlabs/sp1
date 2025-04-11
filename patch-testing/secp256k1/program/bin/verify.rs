#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let times = sp1_zkvm::io::read::<u8>();

    for i in 0..times {
        println!("{}", i);
        let msg_digest = sp1_zkvm::io::read_vec();
        let signature = sp1_zkvm::io::read_vec();
        let pubkey_v0_29_1 = sp1_zkvm::io::read::<secp256k1_v0_29_1::PublicKey>();
        let pubkey_v0_30_0 = sp1_zkvm::io::read::<secp256k1_v0_30_0::PublicKey>();
        sp1_zkvm::io::commit(&(
            inner_verify_v0_29_1(&msg_digest, &signature, &pubkey_v0_29_1),
            inner_verify_v0_30_0(&msg_digest, &signature, &pubkey_v0_30_0),
        ));
    }
}

fn inner_verify_v0_29_1(
    msg_digest: &[u8],
    signature: &[u8],
    pubkey: &secp256k1_v0_29_1::PublicKey,
) -> bool {
    use secp256k1_v0_29_1::{ecdsa::Signature, Message, PublicKey, Secp256k1};

    let message = Message::from_digest_slice(msg_digest).unwrap();
    let signature = Signature::from_der(signature).unwrap();
    let secp = Secp256k1::new();

    secp.verify_ecdsa(&message, &signature, &pubkey).is_ok()
}

fn inner_verify_v0_30_0(
    msg_digest: &[u8],
    signature: &[u8],
    pubkey: &secp256k1_v0_30_0::PublicKey,
) -> bool {
    use secp256k1_v0_30_0::{ecdsa::Signature, Message, PublicKey, Secp256k1};

    let message = Message::from_digest_slice(msg_digest).unwrap();
    let signature = Signature::from_der(signature).unwrap();
    let secp = Secp256k1::new();

    secp.verify_ecdsa(message, &signature, &pubkey).is_ok()
}
