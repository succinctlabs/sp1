#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::{address, bytes};
use alloy_primitives::{B256, B512, Bytes};

// Emits SECP256K1_ADD, SECP256K1_DOUBLE, and SECP256K1_DECOMPRESS syscalls.
/// Source: https://github.com/alloy-rs/core/blob/adcf7adfa1f35c56e6331bab85b8c56d32a465f1/crates/primitives/src/signature/sig.rs#L620-L631
pub fn main() {
    // A valid signature.
    let precompile_input = bytes!("a79c77e94d0cd778e606e61130d9065e718eced9408e63df3a71919d5830d82d000000000000000000000000000000000000000000000000000000000000001cd685e79fb0b7ff849cbc6283dd1174b4a06f2aa556f019169a99396fc052b42e2c0ff35d08662f2685929c20ce8eaab568a404d61cf2aa837f1f431e2aef6211");

    let msg = <&B256>::try_from(&precompile_input[0..32]).unwrap();
    let recid = precompile_input[63] - 27;
    println!("recid: {}", recid);
    let sig = <&B512>::try_from(&precompile_input[64..128]).unwrap();

    println!("cycle-tracker-start: k256 verify");
    let _: Bytes = revm_precompile::secp256k1::ecrecover(sig, recid, msg)
        .map(|o| o.to_vec().into())
        .unwrap_or_default();
    println!("cycle-tracker-end: k256 verify");

    // Signature by the 0x1 private key. Confirms that multi_scalar_multiplication works as intended.
    let precompile_input = bytes!("15499a876f0d57fdc360c760aec98245eba1902610140c14d5f0c3c0284e28a7000000000000000000000000000000000000000000000000000000000000001c2106219ec2e5ef9f7d5ffb303fac05c4066e66db6d501d2e5b1626f2cc8fbe1c316d4e90b09819db9c261017f18e1b5b105855922ec962fd58e83c943e4c4ba3");

    let msg = <&B256>::try_from(&precompile_input[0..32]).unwrap();
    let recid = precompile_input[63] - 27;
    let sig = <&B512>::try_from(&precompile_input[64..128]).unwrap();

    println!("cycle-tracker-start: k256 verify");
    let recovered_address: Bytes = revm_precompile::secp256k1::ecrecover(sig, recid, msg)
        .map(|o| o.to_vec().into())
        .unwrap_or_default();
    println!("cycle-tracker-end: k256 verify");

    println!("recovered_address: {:?}", recovered_address);

    let _ = address!("ea532f4122fb1152b506b545c67e110d276e3448");
}
