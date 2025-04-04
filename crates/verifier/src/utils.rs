use bn::Fr;
#[cfg(not(feature = "blake3"))]
use sha2::{Digest, Sha256};

use crate::error::Error;

/// Hashes the public inputs in the same format as the Plonk and Groth16 verifiers.
/// Uses `Sha256`, or `Blake3` if the `blake3` feature is enabled.
pub fn hash_public_inputs(public_inputs: &[u8]) -> [u8; 32] {
    let mut result = hash(public_inputs);

    // The Plonk and Groth16 verifiers operate over a 254 bit field, so we need to zero
    // out the first 3 bits. The same logic happens in the SP1 Ethereum verifier contract.
    result[0] &= 0x1F;

    result
}

/// Hashes the public input using `Sha256`, or `Blake3` if the `blake3` feature
/// is enabled.
pub fn hash(inputs: &[u8]) -> [u8; 32] {
    cfg_if::cfg_if! {
        if #[cfg(feature = "blake3")] {
            *blake3::hash(inputs).as_bytes()
        }
        else {
            Sha256::digest(inputs).into()
        }
    }
}

/// Formats the sp1 vkey hash and public inputs for use in either the Plonk or Groth16 verifier.
pub fn bn254_public_values(sp1_vkey_hash: &[u8; 32], sp1_public_inputs: &[u8]) -> [Fr; 2] {
    let committed_values_digest = hash_public_inputs(sp1_public_inputs);
    let vkey_hash = Fr::from_slice(&sp1_vkey_hash[1..]).unwrap();
    let committed_values_digest = Fr::from_slice(&committed_values_digest).unwrap();
    [vkey_hash, committed_values_digest]
}

/// Decodes the sp1 vkey hash from the string from a call to `vk.bytes32`.
pub fn decode_sp1_vkey_hash(sp1_vkey_hash: &str) -> Result<[u8; 32], Error> {
    let bytes = hex::decode(&sp1_vkey_hash[2..]).map_err(|_| Error::InvalidProgramVkeyHash)?;
    bytes.try_into().map_err(|_| Error::InvalidProgramVkeyHash)
}
