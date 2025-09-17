use alloc::vec::Vec;

use crate::{
    constants::{COMPRESSED_GROTH16_PROOF_LENGTH, GROTH16_PROOF_LENGTH},
    converter::{
        compress_g1_point_to_x, compress_g2_point_to_x, g1_point_to_uncompressed_bytes,
        g2_point_to_uncompressed_bytes, unchecked_compressed_x_to_g1_point,
        unchecked_compressed_x_to_g2_point, uncompressed_bytes_to_g1_point,
        uncompressed_bytes_to_g2_point,
    },
    error::Error,
    groth16::{Groth16G1, Groth16G2, Groth16Proof, Groth16VerifyingKey},
};

use super::error::Groth16Error;

/// Compress the Groth16 proof from a byte slice to a compressed byte slice.
///
/// The compressed byte slice is represented as 2 compressed g1 points, and one compressed g2 point,
/// as outputted from Gnark.
pub fn compress_groth16_proof_from_bytes(
    buf: &[u8],
) -> Result<[u8; COMPRESSED_GROTH16_PROOF_LENGTH], Groth16Error> {
    if buf.len() < GROTH16_PROOF_LENGTH {
        return Err(Groth16Error::GeneralError(Error::InvalidData));
    }

    let proof = load_groth16_proof_from_bytes(buf)?;
    let mut buffer = [0u8; COMPRESSED_GROTH16_PROOF_LENGTH];
    buffer[..32].copy_from_slice(&compress_g1_point_to_x(&proof.ar)?);
    buffer[32..96].copy_from_slice(&compress_g2_point_to_x(&proof.bs)?);
    buffer[96..128].copy_from_slice(&compress_g1_point_to_x(&proof.krs)?);

    Ok(buffer)
}

/// Decompress the Groth16 proof from a compressed byte slice to a byte slice.
///
/// The byte slice is represented as 2 uncompressed g1 points, and one uncompressed g2 point,
/// as outputted from Gnark.
pub fn decompress_groth16_proof_from_bytes(
    buf: &[u8],
) -> Result<[u8; GROTH16_PROOF_LENGTH], Groth16Error> {
    if buf.len() < COMPRESSED_GROTH16_PROOF_LENGTH {
        return Err(Groth16Error::GeneralError(Error::InvalidData));
    }

    let proof = load_compressed_groth16_proof_from_bytes(buf)?;
    let mut buffer = [0u8; GROTH16_PROOF_LENGTH];
    buffer[..64].copy_from_slice(&g1_point_to_uncompressed_bytes(&proof.ar)?);
    buffer[64..192].copy_from_slice(&g2_point_to_uncompressed_bytes(&proof.bs)?);
    buffer[192..256].copy_from_slice(&g1_point_to_uncompressed_bytes(&proof.krs)?);

    Ok(buffer)
}

/// Load the Groth16 proof from the given byte slice.
///
/// The byte slice is represented as 2 uncompressed g1 points, and one uncompressed g2 point,
/// as outputted from Gnark.
pub(crate) fn load_groth16_proof_from_bytes(buffer: &[u8]) -> Result<Groth16Proof, Groth16Error> {
    if buffer.len() < GROTH16_PROOF_LENGTH {
        return Err(Groth16Error::GeneralError(Error::InvalidData));
    }
    let (ar, bs, krs) = (
        uncompressed_bytes_to_g1_point(&buffer[..64])?,
        uncompressed_bytes_to_g2_point(&buffer[64..192])?,
        uncompressed_bytes_to_g1_point(&buffer[192..256])?,
    );

    Ok(Groth16Proof { ar, bs, krs })
}

/// Load the compressed Groth16 proof from the given byte slice.
///
/// The byte slice is represented as 2 compressed g1 points, and one compressed g2 point,
/// as outputted from Gnark.
pub(crate) fn load_compressed_groth16_proof_from_bytes(
    buffer: &[u8],
) -> Result<Groth16Proof, Groth16Error> {
    if buffer.len() < COMPRESSED_GROTH16_PROOF_LENGTH {
        return Err(Groth16Error::GeneralError(Error::InvalidData));
    }
    let (ar, bs, krs) = (
        unchecked_compressed_x_to_g1_point(&buffer[..32])?,
        unchecked_compressed_x_to_g2_point(&buffer[32..96])?,
        unchecked_compressed_x_to_g1_point(&buffer[96..128])?,
    );

    Ok(Groth16Proof { ar, bs, krs })
}

/// Load the Groth16 verification key from the given byte slice.
///
/// The gnark verification key includes a lot of extraneous information. We only extract the
/// necessary elements to verify a proof.
pub(crate) fn load_groth16_verifying_key_from_bytes(
    buffer: &[u8],
) -> Result<Groth16VerifyingKey, Groth16Error> {
    // We don't need to check each compressed point because the Groth16 vkey is a public constant
    // that doesn't usually change. The party using the Groth16 vkey will usually clearly know
    // how the vkey was generated.
    let g1_alpha = unchecked_compressed_x_to_g1_point(&buffer[..32])?;
    let g2_beta = unchecked_compressed_x_to_g2_point(&buffer[64..128])?;
    let g2_gamma = unchecked_compressed_x_to_g2_point(&buffer[128..192])?;
    let g2_delta = unchecked_compressed_x_to_g2_point(&buffer[224..288])?;

    let num_k = u32::from_be_bytes([buffer[288], buffer[289], buffer[290], buffer[291]]);
    let mut k = Vec::new();
    let mut offset = 292;
    for _ in 0..num_k {
        let point = unchecked_compressed_x_to_g1_point(&buffer[offset..offset + 32])?;
        k.push(point);
        offset += 32;
    }

    Ok(Groth16VerifyingKey {
        g1: Groth16G1 { alpha: g1_alpha, k },
        g2: Groth16G2 { beta: -g2_beta, gamma: g2_gamma, delta: g2_delta },
    })
}
