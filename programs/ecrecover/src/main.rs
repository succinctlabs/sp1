#![no_main]
extern crate succinct_zkvm;
succinct_zkvm::entrypoint!(main);

use hex_literal::hex;
use succinct_precompiles::secp256k1::{decompress_pubkey, verify_signature};
use succinct_zkvm::{io, unconstrained};

pub fn main() {
    // recovery param: 1
    // message: 5c868fedb8026979ebd26f1ba07c27eedf4ff6d10443505a96ecaf21ba8c4f0937b3cd23ffdc3dd429d4cd1905fb8dbcceeff1350020e18b58d2ba70887baa3a9b783ad30d3fbf210331cdd7df8d77defa398cdacdfc2e359c7ba4cae46bb74401deb417f8b912a1aa966aeeba9c39c7dd22479ae2b30719dca2f2206c5eb4b7
    // pubkey compressed: 034a071e8a6e10aada2b8cf39fa3b5fb3400b04e99ea8ae64ceea1a977dbeaf5d5
    // pubkey: 044a071e8a6e10aada2b8cf39fa3b5fb3400b04e99ea8ae64ceea1a977dbeaf5d5f8c8fbd10b71ab14cd561f7df8eb6da50f8a8d81ba564342244d26d1d4211595

    let msg_hash = hex!("5ae8317d34d1e595e3fa7247db80c0af4320cce1116de187f8f7e2e099c0d8d0");
    let sig = hex!("45c0b7f8c09a9e1f1cea0c25785594427b6bf8f9f878a8af0b1abbb48e16d0920d8becd0c220f67c51217eecfd7184ef0732481c843857e6bc7fc095c4f6b78801");

    unconstrained! {
        use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
        println!("msg_hash: {:?}", msg_hash);
        // parse signature
        let mut recid = sig[64];
        let mut sig = Signature::from_slice(&sig[..64]).unwrap();

        // normalize signature and flip recovery id if needed.
        if let Some(sig_normalized) = sig.normalize_s() {
            sig = sig_normalized;
            recid ^= 1
        };
        let recid = RecoveryId::from_byte(recid).expect("Recovery id is valid");

        // recover key
        let recovered_key = VerifyingKey::recover_from_prehash(&msg_hash[..], &sig, recid).unwrap();
        println!("recovered_key: {:?}", recovered_key);
        let bytes = recovered_key.to_sec1_bytes();
        println!("bytes: {:?}", bytes);
        io::hint_slice(&bytes);
    }

    let mut recovered_bytes = [0_u8; 33];
    io::read_slice(&mut recovered_bytes);
    println!("recovered_bytes: {:?}", recovered_bytes);

    let decompressed = decompress_pubkey(&recovered_bytes).unwrap();
    println!("decompressed: {:?}", decompressed);

    let sig_bytes: [u8; 64] = sig[..64].try_into().unwrap();
    let k256_sig = k256::ecdsa::Signature::from_bytes((&sig_bytes).into()).unwrap();

    let verified = verify_signature(&decompressed, &msg_hash, &k256_sig, None);
    println!("verified: {:?}", verified);
}
