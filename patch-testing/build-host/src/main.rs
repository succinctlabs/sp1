pub use bls12_381_patched;
pub use crypto_bigint_patched;
pub use curve25519_dalek_ng_patched;
pub use curve25519_dalek_patched;
pub use ecdsa_core_patched;
pub use rsa_patched;
pub use secp256k1_patched;
pub use sha2_v0_10_6_patched;
pub use sha2_v0_10_8_patched;
pub use sha3_v0_10_8_patched;
pub use substrate_bn_patched;
pub use tiny_keccak_patched;

fn main() {
    // Note: This file is a dummy that merely imports all the patches, to ensure that they build correctly outside our vm.
}
