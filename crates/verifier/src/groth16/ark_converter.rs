use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use thiserror::Error;

const GNARK_MASK: u8 = 0b11 << 6;
const GNARK_COMPRESSED_POSITIVE: u8 = 0b10 << 6;
const GNARK_COMPRESSED_NEGATIVE: u8 = 0b11 << 6;
const GNARK_COMPRESSED_INFINITY: u8 = 0b01 << 6;

const ARK_MASK: u8 = 0b11 << 6;
const ARK_COMPRESSED_POSITIVE: u8 = 0b00 << 6;
const ARK_COMPRESSED_NEGATIVE: u8 = 0b10 << 6;
const ARK_COMPRESSED_INFINITY: u8 = 0b01 << 6;

#[derive(Error, Debug)]
pub enum ArkGroth16Error {
    #[error("G1 compression error")]
    G1CompressionError,
    #[error("G2 compression error")]
    G2CompressionError,
    #[error("Invalid input")]
    InvalidInput,
}

/// Convert the endianness of a byte array, chunk by chunk.
///
/// Taken from https://github.com/anza-xyz/agave/blob/c54d840/curves/bn254/src/compression.rs#L176-L189
fn convert_endianness<const CHUNK_SIZE: usize, const ARRAY_SIZE: usize>(
    bytes: &[u8; ARRAY_SIZE],
) -> [u8; ARRAY_SIZE] {
    let reversed: [_; ARRAY_SIZE] = bytes
        .chunks_exact(CHUNK_SIZE)
        .flat_map(|chunk| chunk.iter().rev().copied())
        .enumerate()
        .fold([0u8; ARRAY_SIZE], |mut acc, (i, v)| {
            acc[i] = v;
            acc
        });
    reversed
}

/// Decompress a G1 point.
///
/// Taken from https://github.com/anza-xyz/agave/blob/c54d840/curves/bn254/src/compression.rs#L219
fn decompress_g1(g1_bytes: &[u8; 32]) -> Result<G1Affine, ArkGroth16Error> {
    let g1_bytes = gnark_compressed_x_to_ark_compressed_x(g1_bytes)?;
    let g1_bytes = convert_endianness::<32, 32>(&g1_bytes.as_slice().try_into().unwrap());
    let decompressed_g1 = G1Affine::deserialize_with_mode(
        convert_endianness::<32, 32>(&g1_bytes).as_slice(),
        Compress::Yes,
        Validate::No,
    )
    .map_err(|_| ArkGroth16Error::G1CompressionError)?;
    Ok(decompressed_g1)
}

/// Decompress a G2 point.
///
/// Adapted from https://github.com/anza-xyz/agave/blob/c54d840/curves/bn254/src/compression.rs#L255
fn decompress_g2(g2_bytes: &[u8; 64]) -> Result<G2Affine, ArkGroth16Error> {
    let g2_bytes = gnark_compressed_x_to_ark_compressed_x(g2_bytes)?;
    let g2_bytes = convert_endianness::<64, 64>(&g2_bytes.as_slice().try_into().unwrap());
    let decompressed_g2 = G2Affine::deserialize_with_mode(
        convert_endianness::<64, 64>(&g2_bytes).as_slice(),
        Compress::Yes,
        Validate::No,
    )
    .map_err(|_| ArkGroth16Error::G2CompressionError)?;
    Ok(decompressed_g2)
}

fn gnark_flag_to_ark_flag(msb: u8) -> Result<u8, ArkGroth16Error> {
    let gnark_flag = msb & GNARK_MASK;

    let ark_flag = match gnark_flag {
        GNARK_COMPRESSED_POSITIVE => ARK_COMPRESSED_POSITIVE,
        GNARK_COMPRESSED_NEGATIVE => ARK_COMPRESSED_NEGATIVE,
        GNARK_COMPRESSED_INFINITY => ARK_COMPRESSED_INFINITY,
        _ => {
            return Err(ArkGroth16Error::InvalidInput);
        }
    };

    Ok(msb & !ARK_MASK | ark_flag)
}

fn gnark_compressed_x_to_ark_compressed_x(x: &[u8]) -> Result<Vec<u8>, ArkGroth16Error> {
    if x.len() != 32 && x.len() != 64 {
        return Err(ArkGroth16Error::InvalidInput);
    }
    let mut x_copy = x.to_owned();

    let msb = gnark_flag_to_ark_flag(x_copy[0])?;
    x_copy[0] = msb;

    x_copy.reverse();
    Ok(x_copy)
}

/// Deserialize a gnark decompressed affine G1 point to an arkworks decompressed affine G1 point.
fn gnark_decompressed_g1_to_ark_decompressed_g1(
    buf: &[u8; 64],
) -> Result<G1Affine, ArkGroth16Error> {
    let buf = convert_endianness::<32, 64>(buf);
    if buf == [0u8; 64] {
        return Ok(G1Affine::zero());
    }
    let g1 = G1Affine::deserialize_with_mode(
        &*[&buf[..], &[0u8][..]].concat(),
        Compress::No,
        Validate::Yes,
    )
    .map_err(|_| ArkGroth16Error::G1CompressionError)?;
    Ok(g1)
}

/// Deserialize a gnark decompressed affine G2 point to an arkworks decompressed affine G2 point.
fn gnark_decompressed_g2_to_ark_decompressed_g2(
    buf: &[u8; 128],
) -> Result<G2Affine, ArkGroth16Error> {
    let buf = convert_endianness::<64, 128>(buf);
    if buf == [0u8; 128] {
        return Ok(G2Affine::zero());
    }
    let g2 = G2Affine::deserialize_with_mode(
        &*[&buf[..], &[0u8][..]].concat(),
        Compress::No,
        Validate::Yes,
    )
    .map_err(|_| ArkGroth16Error::G2CompressionError)?;
    Ok(g2)
}

/// Load a Groth16 proof from bytes in the arkworks format.
pub fn load_ark_proof_from_bytes(buffer: &[u8]) -> Result<Proof<Bn254>, ArkGroth16Error> {
    Ok(Proof::<Bn254> {
        a: gnark_decompressed_g1_to_ark_decompressed_g1(buffer[..64].try_into().unwrap())?,
        b: gnark_decompressed_g2_to_ark_decompressed_g2(buffer[64..192].try_into().unwrap())?,
        c: gnark_decompressed_g1_to_ark_decompressed_g1(&buffer[192..256].try_into().unwrap())?,
    })
}

/// Load a Groth16 verifying key from bytes in the arkworks format.
pub fn load_ark_groth16_verifying_key_from_bytes(
    buffer: &[u8],
) -> Result<VerifyingKey<Bn254>, ArkGroth16Error> {
    // Note that g1_beta and g1_delta are not used in the verification process.
    let alpha_g1 = decompress_g1(buffer[..32].try_into().unwrap())?;
    let beta_g2 = decompress_g2(buffer[64..128].try_into().unwrap())?;
    let gamma_g2 = decompress_g2(buffer[128..192].try_into().unwrap())?;
    let delta_g2 = decompress_g2(buffer[224..288].try_into().unwrap())?;

    let num_k = u32::from_be_bytes([buffer[288], buffer[289], buffer[290], buffer[291]]);
    let mut k = Vec::new();
    let mut offset = 292;
    for _ in 0..num_k {
        let point = decompress_g1(&buffer[offset..offset + 32].try_into().unwrap())?;
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

    Ok(VerifyingKey { alpha_g1, beta_g2, gamma_g2, delta_g2, gamma_abc_g1: k })
}

/// Load the public inputs from the bytes in the arkworks format.
///
/// This reads the vkey hash and the committed values digest as big endian Fr elements.
pub fn load_ark_public_inputs_from_bytes(
    vkey_hash: &[u8; 32],
    committed_values_digest: &[u8; 32],
) -> [Fr; 2] {
    [Fr::from_be_bytes_mod_order(vkey_hash), Fr::from_be_bytes_mod_order(committed_values_digest)]
}
