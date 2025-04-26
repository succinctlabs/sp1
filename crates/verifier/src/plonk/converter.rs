use crate::{
    constants::{
        PLONK_CLAIMED_VALUES_COUNT, PLONK_CLAIMED_VALUES_OFFSET, PLONK_Z_SHIFTED_OPENING_H_OFFSET,
        PLONK_Z_SHIFTED_OPENING_VALUE_OFFSET,
    },
    converter::{
        unchecked_compressed_x_to_g1_point, unchecked_compressed_x_to_g2_point,
        uncompressed_bytes_to_g1_point,
    },
    error::Error,
};
use alloc::vec::Vec;
use bn::{AffineG1, Fr, G2};

use super::{
    error::PlonkError,
    kzg::{self, BatchOpeningProof, LineEvaluationAff, OpeningProof, E2},
    verify::PlonkVerifyingKey,
    PlonkProof,
};

pub(crate) fn load_plonk_verifying_key_from_bytes(
    buffer: &[u8],
) -> Result<PlonkVerifyingKey, PlonkError> {
    let size = u64::from_be_bytes([
        buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7],
    ]) as usize;
    let size_inv =
        Fr::from_slice(&buffer[8..40]).map_err(|e| PlonkError::GeneralError(Error::Field(e)))?;
    let generator =
        Fr::from_slice(&buffer[40..72]).map_err(|e| PlonkError::GeneralError(Error::Field(e)))?;

    let nb_public_variables = u64::from_be_bytes([
        buffer[72], buffer[73], buffer[74], buffer[75], buffer[76], buffer[77], buffer[78],
        buffer[79],
    ]) as usize;

    let coset_shift =
        Fr::from_slice(&buffer[80..112]).map_err(|e| PlonkError::GeneralError(Error::Field(e)))?;
    let s0 = unchecked_compressed_x_to_g1_point(&buffer[112..144])?;
    let s1 = unchecked_compressed_x_to_g1_point(&buffer[144..176])?;
    let s2 = unchecked_compressed_x_to_g1_point(&buffer[176..208])?;
    let ql = unchecked_compressed_x_to_g1_point(&buffer[208..240])?;
    let qr = unchecked_compressed_x_to_g1_point(&buffer[240..272])?;
    let qm = unchecked_compressed_x_to_g1_point(&buffer[272..304])?;
    let qo = unchecked_compressed_x_to_g1_point(&buffer[304..336])?;
    let qk = unchecked_compressed_x_to_g1_point(&buffer[336..368])?;
    let num_qcp = u32::from_be_bytes([buffer[368], buffer[369], buffer[370], buffer[371]]);
    let mut qcp = Vec::new();
    let mut offset = 372;

    for _ in 0..num_qcp {
        let point = unchecked_compressed_x_to_g1_point(&buffer[offset..offset + 32])?;
        qcp.push(point);
        offset += 32;
    }

    let g1 = unchecked_compressed_x_to_g1_point(&buffer[offset..offset + 32])?;
    let g2_0 = unchecked_compressed_x_to_g2_point(&buffer[offset + 32..offset + 96])?;
    let g2_1 = unchecked_compressed_x_to_g2_point(&buffer[offset + 96..offset + 160])?;

    offset += 160 + 33788;

    let num_commitment_constraint_indexes = u64::from_be_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
        buffer[offset + 4],
        buffer[offset + 5],
        buffer[offset + 6],
        buffer[offset + 7],
    ]) as usize;

    let mut commitment_constraint_indexes = Vec::new();
    offset += 8;
    for _ in 0..num_commitment_constraint_indexes {
        let index = u64::from_be_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
            buffer[offset + 4],
            buffer[offset + 5],
            buffer[offset + 6],
            buffer[offset + 7],
        ]) as usize;
        commitment_constraint_indexes.push(index);
        offset += 8;
    }

    let result = PlonkVerifyingKey {
        size,
        size_inv,
        generator,
        nb_public_variables,
        kzg: kzg::KZGVerifyingKey {
            g2: [G2::from(g2_0), G2::from(g2_1)],
            g1: g1.into(),
            lines: [[[LineEvaluationAff {
                r0: E2 { a0: Fr::zero(), a1: Fr::zero() },
                r1: E2 { a0: Fr::zero(), a1: Fr::zero() },
            }; 66]; 2]; 2],
        },
        coset_shift,
        s: [s0, s1, s2],
        ql,
        qr,
        qm,
        qo,
        qk,
        qcp,
        commitment_constraint_indexes,
    };

    Ok(result)
}

/// See https://github.com/jtguibas/gnark/blob/26e3df73fc223292be8b7fc0b7451caa4059a649/backend/plonk/bn254/solidity.go
/// for how the proof is serialized.
pub(crate) fn load_plonk_proof_from_bytes(
    buffer: &[u8],
    num_bsb22_commitments: usize,
) -> Result<PlonkProof, PlonkError> {
    if buffer.len() <
        PLONK_CLAIMED_VALUES_OFFSET +
            PLONK_CLAIMED_VALUES_COUNT * 32 +
            PLONK_Z_SHIFTED_OPENING_VALUE_OFFSET +
            PLONK_Z_SHIFTED_OPENING_H_OFFSET +
            num_bsb22_commitments * 32 +
            num_bsb22_commitments * 64
    {
        return Err(PlonkError::GeneralError(Error::InvalidData));
    }

    let lro0 = uncompressed_bytes_to_g1_point(&buffer[..64])?;
    let lro1 = uncompressed_bytes_to_g1_point(&buffer[64..128])?;
    let lro2 = uncompressed_bytes_to_g1_point(&buffer[128..192])?;
    let h0 = uncompressed_bytes_to_g1_point(&buffer[192..256])?;
    let h1 = uncompressed_bytes_to_g1_point(&buffer[256..320])?;
    let h2 = uncompressed_bytes_to_g1_point(&buffer[320..384])?;

    // Stores l_at_zeta, r_at_zeta, o_at_zeta, s 1_at_zeta, s2_at_zeta, bsb22_commitments
    let mut claimed_values = Vec::with_capacity(PLONK_CLAIMED_VALUES_COUNT + num_bsb22_commitments);
    let mut offset = PLONK_CLAIMED_VALUES_OFFSET;
    for _ in 0..PLONK_CLAIMED_VALUES_COUNT {
        let value = Fr::from_slice(&buffer[offset..offset + 32])
            .map_err(|e| PlonkError::GeneralError(Error::Field(e)))?;
        claimed_values.push(value);
        offset += 32;
    }

    let z = uncompressed_bytes_to_g1_point(&buffer[offset..offset + 64])?;
    let z_shifted_opening_value = Fr::from_slice(&buffer[offset + 64..offset + 96])
        .map_err(|e| PlonkError::GeneralError(Error::Field(e)))?;
    offset += PLONK_Z_SHIFTED_OPENING_VALUE_OFFSET;

    let batched_proof_h = uncompressed_bytes_to_g1_point(&buffer[offset..offset + 64])?;
    let z_shifted_opening_h = uncompressed_bytes_to_g1_point(&buffer[offset + 64..offset + 128])?;
    offset += PLONK_Z_SHIFTED_OPENING_H_OFFSET;

    for _ in 0..num_bsb22_commitments {
        let commitment = Fr::from_slice(&buffer[offset..offset + 32])
            .map_err(|e| PlonkError::GeneralError(Error::Field(e)))?;
        claimed_values.push(commitment);
        offset += 32;
    }

    let mut bsb22_commitments = Vec::with_capacity(num_bsb22_commitments);
    for _ in 0..num_bsb22_commitments {
        let commitment = uncompressed_bytes_to_g1_point(&buffer[offset..offset + 64])?;
        bsb22_commitments.push(commitment);
        offset += 64;
    }

    let result = PlonkProof {
        lro: [lro0, lro1, lro2],
        z,
        h: [h0, h1, h2],
        bsb22_commitments,
        batched_proof: BatchOpeningProof { h: batched_proof_h, claimed_values },
        z_shifted_opening: OpeningProof {
            h: z_shifted_opening_h,
            claimed_value: z_shifted_opening_value,
        },
    };

    Ok(result)
}

pub(crate) fn g1_to_bytes(g1: &AffineG1) -> Result<Vec<u8>, PlonkError> {
    let mut bytes: [u8; 64] = unsafe { core::mem::transmute(*g1) };
    bytes[..32].reverse();
    bytes[32..].reverse();
    Ok(bytes.to_vec())
}
