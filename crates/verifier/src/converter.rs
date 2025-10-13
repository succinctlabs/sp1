use core::cmp::Ordering;

use bn::{AffineG1, AffineG2, Fq, Fq2};

use crate::{
    constants::{CompressedPointFlag, MASK},
    error::Error,
};

/// Compresse an G1 point to a buffer.
///
/// This is a reveresed function against `unchecked_compressed_x_to_g1_point`, return the compressed
/// G1 point which hardcoded the sign flag of y coordinate.
pub fn compress_g1_point_to_x(g1: &AffineG1) -> Result<[u8; 32], Error> {
    let mut x_bytes = [0u8; 32];
    g1.x().to_big_endian(&mut x_bytes).map_err(Error::Field)?;

    if g1.y() > -g1.y() {
        x_bytes[0] |= CompressedPointFlag::Negative as u8;
    } else {
        x_bytes[0] = (x_bytes[0] & !MASK) | (CompressedPointFlag::Positive as u8);
    }

    Ok(x_bytes)
}

/// Compresse an G2 point to a buffer.
///
/// This is a reveresed function against `unchecked_compressed_x_to_g1_point`, return the compressed
/// G2 point which hardcoded the sign flag of y coordinate.
pub fn compress_g2_point_to_x(g2: &AffineG2) -> Result<[u8; 64], Error> {
    let mut x_bytes = [0u8; 64];
    let x1 = Fq::from_u256(g2.x().0.imaginary().0).map_err(Error::Field)?;
    let x0 = Fq::from_u256(g2.x().0.real().0).map_err(Error::Field)?;
    x1.to_big_endian(&mut x_bytes[..32]).map_err(Error::Field)?;
    x0.to_big_endian(&mut x_bytes[32..64]).map_err(Error::Field)?;

    if g2.y().0 > -g2.y().0 {
        x_bytes[0] |= CompressedPointFlag::Negative as u8;
    } else {
        x_bytes[0] = (x_bytes[0] & !MASK) | (CompressedPointFlag::Positive as u8);
    }

    Ok(x_bytes)
}

/// Deserializes an Fq element from a buffer.
///
/// If this Fq element is part of a compressed point, the flag that indicates the sign of the
/// y coordinate is also returned.
pub fn deserialize_with_flags(buf: &[u8]) -> Result<(Fq, CompressedPointFlag), Error> {
    if buf.len() != 32 {
        return Err(Error::InvalidXLength);
    };

    let m_data = buf[0] & MASK;
    if m_data == u8::from(CompressedPointFlag::Infinity) {
        // Checks if the first byte is zero after masking AND the rest of the bytes are zero.
        if buf[0] & !MASK == 0 && buf[1..].iter().all(|&b| b == 0) {
            return Err(Error::InvalidPoint);
        }
        Ok((Fq::zero(), CompressedPointFlag::Infinity))
    } else {
        let mut x_bytes: [u8; 32] = [0u8; 32];
        x_bytes.copy_from_slice(buf);
        x_bytes[0] &= !MASK;

        let x = Fq::from_be_bytes_mod_order(&x_bytes).expect("Failed to convert x bytes to Fq");

        Ok((x, m_data.into()))
    }
}

/// Converts a compressed G1 point to an AffineG1 point.
///
/// Asserts that the compressed point is represented as a single fq element: the x coordinate
/// of the point. The y coordinate is then computed from the x coordinate. The final point
/// is not checked to be on the curve for efficiency.
pub fn unchecked_compressed_x_to_g1_point(buf: &[u8]) -> Result<AffineG1, Error> {
    let (x, m_data) = deserialize_with_flags(buf)?;
    let (y, neg_y) = AffineG1::get_ys_from_x_unchecked(x).ok_or(Error::InvalidPoint)?;

    let mut final_y = y;
    if y.cmp(&neg_y) == Ordering::Greater {
        if m_data == CompressedPointFlag::Positive {
            final_y = -y;
        }
    } else if m_data == CompressedPointFlag::Negative {
        final_y = -y;
    }

    Ok(AffineG1::new_unchecked(x, final_y))
}

/// Converts an uncompressed G1 point to an AffineG1 point.
///
/// Asserts that the affine point is represented as two fq elements.
pub fn uncompressed_bytes_to_g1_point(buf: &[u8]) -> Result<AffineG1, Error> {
    if buf.len() != 64 {
        return Err(Error::InvalidXLength);
    };

    let (x_bytes, y_bytes) = buf.split_at(32);

    let x = Fq::from_slice(x_bytes).map_err(Error::Field)?;
    let y = Fq::from_slice(y_bytes).map_err(Error::Field)?;
    AffineG1::new(x, y).map_err(Error::Group)
}

/// Converts an AffineG1 point to an uncompressed byte array.
///
/// The uncompressed byte array is represented as two fq elements.
pub fn g1_point_to_uncompressed_bytes(point: &AffineG1) -> Result<[u8; 64], Error> {
    let mut buffer = [0u8; 64];
    point.x().to_big_endian(&mut buffer[..32]).map_err(Error::Field)?;
    point.y().to_big_endian(&mut buffer[32..]).map_err(Error::Field)?;

    Ok(buffer)
}

/// Converts a compressed G2 point to an AffineG2 point.
///
/// Asserts that the compressed point is represented as a single fq2 element: the x coordinate
/// of the point.
/// Then, gets the y coordinate from the x coordinate.
/// For efficiency, this function does not check that the final point is on the curve.
pub fn unchecked_compressed_x_to_g2_point(buf: &[u8]) -> Result<AffineG2, Error> {
    if buf.len() != 64 {
        return Err(Error::InvalidXLength);
    };

    let (x1, flag) = deserialize_with_flags(&buf[..32])?;
    let x0 = Fq::from_be_bytes_mod_order(&buf[32..64]).map_err(Error::Field)?;
    let x = Fq2::new(x0, x1);

    if flag == CompressedPointFlag::Infinity {
        return Ok(AffineG2::one());
    }

    let (y, neg_y) = AffineG2::get_ys_from_x_unchecked(x).ok_or(Error::InvalidPoint)?;

    match flag {
        CompressedPointFlag::Positive => Ok(AffineG2::new_unchecked(x, y)),
        CompressedPointFlag::Negative => Ok(AffineG2::new_unchecked(x, neg_y)),
        _ => Err(Error::InvalidPoint),
    }
}

/// Converts an uncompressed G2 point to an AffineG2 point.
///
/// Asserts that the affine point is represented as two fq2 elements.
pub fn uncompressed_bytes_to_g2_point(buf: &[u8]) -> Result<AffineG2, Error> {
    if buf.len() != 128 {
        return Err(Error::InvalidXLength);
    }

    let (x_bytes, y_bytes) = buf.split_at(64);
    let (x1_bytes, x0_bytes) = x_bytes.split_at(32);
    let (y1_bytes, y0_bytes) = y_bytes.split_at(32);

    let x1 = Fq::from_slice(x1_bytes).map_err(Error::Field)?;
    let x0 = Fq::from_slice(x0_bytes).map_err(Error::Field)?;
    let y1 = Fq::from_slice(y1_bytes).map_err(Error::Field)?;
    let y0 = Fq::from_slice(y0_bytes).map_err(Error::Field)?;

    let x = Fq2::new(x0, x1);
    let y = Fq2::new(y0, y1);

    AffineG2::new(x, y).map_err(Error::Group)
}

/// Converts an AffineG2 point to an uncompressed byte array.
///
/// The uncompressed byte array is represented as two fq2 elements.
pub fn g2_point_to_uncompressed_bytes(point: &AffineG2) -> Result<[u8; 128], Error> {
    let mut buffer = [0u8; 128];
    Fq::from_u256(point.x().0.imaginary().0)
        .unwrap()
        .to_big_endian(&mut buffer[..32])
        .map_err(Error::Field)?;
    Fq::from_u256(point.x().0.real().0)
        .unwrap()
        .to_big_endian(&mut buffer[32..64])
        .map_err(Error::Field)?;
    Fq::from_u256(point.y().0.imaginary().0)
        .unwrap()
        .to_big_endian(&mut buffer[64..96])
        .map_err(Error::Field)?;
    Fq::from_u256(point.y().0.real().0)
        .unwrap()
        .to_big_endian(&mut buffer[96..128])
        .map_err(Error::Field)?;

    Ok(buffer)
}
