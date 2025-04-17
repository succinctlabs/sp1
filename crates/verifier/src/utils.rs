use bn::Fr;
use sha2::{Digest, Sha256};

use crate::error::Error;

/// Hashes the public inputs in the same format as the Plonk and Groth16 verifiers.
/// Uses `Sha256`.
pub fn hash_public_inputs(public_inputs: &[u8]) -> [u8; 32] {
    hash_public_inputs_with_fn(public_inputs, sha256_hash)
}

/// Hashes the public inputs in the same format as the Plonk and Groth16 verifiers,
/// using the provided hash function.
pub fn hash_public_inputs_with_fn<F>(public_inputs: &[u8], hasher: F) -> [u8; 32]
where
    F: Fn(&[u8]) -> [u8; 32],
{
    let mut result = hasher(public_inputs);

    // The Plonk and Groth16 verifiers operate over a 254 bit field, so we need to zero
    // out the first 3 bits. The same logic happens in the SP1 Ethereum verifier contract.
    result[0] &= 0x1F;

    result
}

/// Hashes the public input using `Sha256`.
pub fn sha256_hash(inputs: &[u8]) -> [u8; 32] {
    Sha256::digest(inputs).into()
}

/// Hash the input using `Blake3`.
pub fn blake3_hash(inputs: &[u8]) -> [u8; 32] {
    *blake3::hash(inputs).as_bytes()
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
