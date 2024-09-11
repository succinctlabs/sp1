use anyhow::{anyhow, Result};

use crate::bn254_verifier::constants::{
    ARK_COMPRESSED_INFINITY, ARK_COMPRESSED_NEGATIVE, ARK_COMPRESSED_POSTIVE, ARK_MASK,
    ERR_INVALID_GNARK_X_LENGTH, ERR_UNEXPECTED_GNARK_FLAG, GNARK_COMPRESSED_INFINITY,
    GNARK_COMPRESSED_NEGATIVE, GNARK_COMPRESSED_POSTIVE, GNARK_MASK,
};

pub fn gnark_flag_to_ark_flag(msb: u8) -> Result<u8> {
    let gnark_flag = msb & GNARK_MASK;

    let ark_flag = match gnark_flag {
        GNARK_COMPRESSED_POSTIVE => ARK_COMPRESSED_POSTIVE,
        GNARK_COMPRESSED_NEGATIVE => ARK_COMPRESSED_NEGATIVE,
        GNARK_COMPRESSED_INFINITY => ARK_COMPRESSED_INFINITY,
        _ => {
            let err_msg = format!("{}: {}", ERR_UNEXPECTED_GNARK_FLAG, gnark_flag);
            return Err(anyhow!(err_msg));
        }
    };

    Ok(msb & !ARK_MASK | ark_flag)
}

/// Convert big-endian gnark compressed x bytes to litte-endian ark compressed x for g1 and g2 point
pub fn gnark_commpressed_x_to_ark_commpressed_x(x: &Vec<u8>) -> Result<Vec<u8>> {
    if x.len() != 32 && x.len() != 64 {
        let err_msg = format!("{}: {}", ERR_INVALID_GNARK_X_LENGTH, x.len());
        return Err(anyhow!(err_msg));
    }
    let mut x_copy = x.clone();

    let msb = gnark_flag_to_ark_flag(x_copy[0])?;
    x_copy[0] = msb;

    x_copy.reverse();
    Ok(x_copy)
}

pub fn is_zeroed(first_byte: u8, buf: &[u8]) -> Result<bool> {
    if first_byte != 0 {
        return Ok(false);
    }
    for &b in buf {
        if b != 0 {
            return Ok(false);
        }
    }

    Ok(true)
}
