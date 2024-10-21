use alloc::{vec, vec::Vec};
use bn::AffineG1;

use crate::{
    converter::{
        unchecked_compressed_x_to_g1_point, unchecked_compressed_x_to_g2_point,
        uncompressed_bytes_to_g1_point, uncompressed_bytes_to_g2_point,
    },
    groth16::{Groth16G1, Groth16G2, Groth16Proof, Groth16VerifyingKey, PedersenVerifyingKey},
};

use super::error::Groth16Error;

pub(crate) fn load_groth16_proof_from_bytes(buffer: &[u8]) -> Result<Groth16Proof, Groth16Error> {
    let ar = uncompressed_bytes_to_g1_point(&buffer[..64])?;
    let bs = uncompressed_bytes_to_g2_point(&buffer[64..192])?;
    let krs = uncompressed_bytes_to_g1_point(&buffer[192..256])?;

    Ok(Groth16Proof { ar, bs, krs, commitments: Vec::new(), commitment_pok: AffineG1::one() })
}

pub(crate) fn load_groth16_verifying_key_from_bytes(
    buffer: &[u8],
) -> Result<Groth16VerifyingKey, Groth16Error> {
    let g1_alpha = unchecked_compressed_x_to_g1_point(&buffer[..32])?;
    let g1_beta = unchecked_compressed_x_to_g1_point(&buffer[32..64])?;
    let g2_beta = unchecked_compressed_x_to_g2_point(&buffer[64..128])?;
    let g2_gamma = unchecked_compressed_x_to_g2_point(&buffer[128..192])?;
    let g1_delta = unchecked_compressed_x_to_g1_point(&buffer[192..224])?;
    let g2_delta = unchecked_compressed_x_to_g2_point(&buffer[224..288])?;

    let num_k = u32::from_be_bytes([buffer[288], buffer[289], buffer[290], buffer[291]]);
    let mut k = Vec::new();
    let mut offset = 292;
    for _ in 0..num_k {
        let point = unchecked_compressed_x_to_g1_point(&buffer[offset..offset + 32])?;
        k.push(point);
        offset += 32;
    }

    let num_of_array_of_public_and_commitment_committed = u32::from_be_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);
    offset += 4;
    for _ in 0..num_of_array_of_public_and_commitment_committed {
        let num = u32::from_be_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
        ]);
        offset += 4;
        for _ in 0..num {
            offset += 4;
        }
    }

    let commitment_key_g = unchecked_compressed_x_to_g2_point(&buffer[offset..offset + 64])?;
    let commitment_key_g_root_sigma_neg =
        unchecked_compressed_x_to_g2_point(&buffer[offset + 64..offset + 128])?;

    Ok(Groth16VerifyingKey {
        g1: Groth16G1 { alpha: g1_alpha, beta: -g1_beta, delta: g1_delta, k },
        g2: Groth16G2 { beta: -g2_beta, gamma: g2_gamma, delta: g2_delta },
        commitment_key: PedersenVerifyingKey {
            g: commitment_key_g,
            g_root_sigma_neg: commitment_key_g_root_sigma_neg,
        },
        public_and_commitment_committed: vec![vec![0u32; 0]],
    })
}
