#![no_main]
sp1_zkvm::entrypoint!(main);

use hex_literal::hex;
use sp1_zkvm::lib::io;
use sp1_zkvm::lib::secp256k1::ecrecover;

pub fn main() {
    // recovery param: 1
    // message: 5c868fedb8026979ebd26f1ba07c27eedf4ff6d10443505a96ecaf21ba8c4f0937b3cd23ffdc3dd429d4cd1905fb8dbcceeff1350020e18b58d2ba70887baa3a9b783ad30d3fbf210331cdd7df8d77defa398cdacdfc2e359c7ba4cae46bb74401deb417f8b912a1aa966aeeba9c39c7dd22479ae2b30719dca2f2206c5eb4b7
    // pubkey compressed: 034a071e8a6e10aada2b8cf39fa3b5fb3400b04e99ea8ae64ceea1a977dbeaf5d5
    // pubkey: 044a071e8a6e10aada2b8cf39fa3b5fb3400b04e99ea8ae64ceea1a977dbeaf5d5f8c8fbd10b71ab14cd561f7df8eb6da50f8a8d81ba564342244d26d1d4211595

    let msg_hash = hex!("5ae8317d34d1e595e3fa7247db80c0af4320cce1116de187f8f7e2e099c0d8d0");
    let sig = hex!(
        "45c0b7f8c09a9e1f1cea0c25785594427b6bf8f9f878a8af0b1abbb48e16d0920d8becd0c220f67c51217eecfd7184ef0732481c843857e6bc7fc095c4f6b78801"
    );

    let pubkey = ecrecover(&sig, &msg_hash).unwrap();
    io::commit_slice(&pubkey);
    println!("pubkey: {:?}", pubkey);
}
