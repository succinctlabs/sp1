use anyhow::{anyhow, Error, Result};
use bn::{AffineG1, AffineG2, Fq, Fq2};
use std::{
    cmp::{Ord, Ordering},
    ops::Neg,
};

use crate::bn254_verifier::{
    constants::{
        GnarkCompressedPointFlag, SerializationError, SerializationError,
        GNARK_COMPRESSED_INFINITY, GNARK_MASK,
    },
    converter::is_zeroed,
};

use groth16_verifier::{
    Groth16G1, Groth16G2, Groth16Proof, Groth16VerifyingKey, PedersenVerifyingKey,
};

fn deserialize_with_flags(buf: &[u8]) -> Result<(Fq, GnarkCompressedPointFlag)> {
    if buf.len() != 32 {
        return Err(anyhow!(SerializationError::InvalidData));
    };

    let m_data = buf[0] & GNARK_MASK;
    if m_data == GNARK_COMPRESSED_INFINITY {
        if !is_zeroed(buf[0] & !GNARK_MASK, &buf[1..32])? {
            return Err(anyhow!(SerializationError::InvalidData));
        }
        Ok((Fq::zero(), GnarkCompressedPointFlag::Infinity))
    } else {
        let mut x_bytes: [u8; 32] = [0u8; 32];
        x_bytes.copy_from_slice(buf);
        x_bytes[0] &= !GNARK_MASK;

        let x = Fq::from_be_bytes_mod_order(&x_bytes.to_vec())
            .expect("Failed to convert x bytes to Fq");

        Ok((x, GnarkCompressedPointFlag::from(m_data)))
    }
}

fn gnark_compressed_x_to_g1_point(buf: &[u8]) -> Result<AffineG1> {
    let (x, m_data) = deserialize_with_flags(buf)?;
    let (y, neg_y) = AffineG1::get_ys_from_x_unchecked(x)
        .ok_or(SerializationError::InvalidData)
        .map_err(Error::msg)?;

    let mut final_y = y;
    if y.cmp(&neg_y) == Ordering::Greater {
        if m_data == GnarkCompressedPointFlag::Positive {
            final_y = y.neg();
        }
    } else {
        if m_data == GnarkCompressedPointFlag::Negative {
            final_y = y.neg();
        }
    }

    Ok(AffineG1::new(x, final_y).map_err(Error::msg)?)
}

fn gnark_compressed_x_to_g2_point(buf: &[u8]) -> Result<AffineG2> {
    if buf.len() != 64 {
        return Err(anyhow!(SerializationError::InvalidData));
    };

    let (x0, _) = deserialize_with_flags(&buf[..32])?;
    let (x1, flag) = deserialize_with_flags(&buf[32..64])?;
    let x = Fq2::new(x0, x1);

    if flag == GnarkCompressedPointFlag::Infinity {
        return Ok(AffineG2::one());
    }

    let (y, neg_y) = AffineG2::get_ys_from_x_unchecked(x)
        .ok_or(SerializationError::InvalidData)
        .map_err(Error::msg)?;

    match flag {
        GnarkCompressedPointFlag::Positive => Ok(AffineG2::new(x, y).map_err(Error::msg)?),
        GnarkCompressedPointFlag::Negative => Ok(AffineG2::new(x, neg_y).map_err(Error::msg)?),
        _ => Err(anyhow!(SerializationError::InvalidData)),
    }
}

pub fn gnark_uncompressed_bytes_to_g1_point(buf: &[u8]) -> Result<AffineG1> {
    if buf.len() != 64 {
        return Err(anyhow!(SerializationError::InvalidData));
    };

    let (x_bytes, y_bytes) = buf.split_at(32);

    let x =
        Fq::from_be_bytes_mod_order(&x_bytes.to_vec()).expect("Failed to convert x bytes to Fq");
    let y =
        Fq::from_be_bytes_mod_order(&y_bytes.to_vec()).expect("Failed to convert y bytes to Fq");

    let mut x_bytes = [0u8; 32];
    x.to_big_endian(&mut x_bytes).expect("Failed to convert x to big endian bytes");
    let mut y_bytes = [0u8; 32];
    y.to_big_endian(&mut y_bytes).expect("Failed to convert y to big endian bytes");

    AffineG1::new(x, y).map_err(|e| anyhow!("Failed to create AffineG1 point: {}", e))
}

pub(crate) fn load_groth16_proof_from_bytes(buffer: &[u8]) -> Result<Groth16Proof> {
    let ar = gnark_compressed_x_to_g1_point(&buffer[..32])?;
    let bs = gnark_compressed_x_to_g2_point(&buffer[32..96])?;
    let krs = gnark_compressed_x_to_g1_point(&buffer[96..128])?;

    Ok(Groth16Proof { ar, bs, krs, commitments: Vec::new(), commitment_pok: AffineG1::one() })
}

pub(crate) fn load_groth16_verifying_key_from_bytes(buffer: &[u8]) -> Result<Groth16VerifyingKey> {
    let g1_alpha = gnark_compressed_x_to_g1_point(&buffer[..32])?;
    let g1_beta = gnark_compressed_x_to_g1_point(&buffer[32..64])?;
    let g2_beta = gnark_compressed_x_to_g2_point(&buffer[64..128])?;
    let g2_gamma = gnark_compressed_x_to_g2_point(&buffer[128..192])?;
    let g1_delta = gnark_compressed_x_to_g1_point(&buffer[192..224])?;
    let g2_delta = gnark_compressed_x_to_g2_point(&buffer[224..288])?;

    let num_k = u32::from_be_bytes([buffer[288], buffer[289], buffer[290], buffer[291]]);
    let mut k = Vec::new();
    let mut offset = 292;
    for _ in 0..num_k {
        let point = gnark_compressed_x_to_g1_point(&buffer[offset..offset + 32])?;
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

    let commitment_key_g = gnark_compressed_x_to_g2_point(&buffer[offset..offset + 64])?;
    let commitment_key_g_root_sigma_neg =
        gnark_compressed_x_to_g2_point(&buffer[offset + 64..offset + 128])?;

    Ok(Groth16VerifyingKey {
        g1: Groth16G1 { alpha: g1_alpha, beta: g1_beta, delta: g1_delta, k },
        g2: Groth16G2 { beta: g2_beta, gamma: g2_gamma, delta: g2_delta },
        commitment_key: PedersenVerifyingKey {
            g: commitment_key_g,
            g_root_sigma_neg: commitment_key_g_root_sigma_neg,
        },
        public_and_commitment_committed: vec![vec![0u32; 0]],
    })
}
