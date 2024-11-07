use core::cmp::Ordering;

use bn::{AffineG1, AffineG2, Fq, Fq2};

use crate::{
    constants::{CompressedPointFlag, MASK},
    error::Error,
};

/// Deserializes an Fq element from a buffer.
///
/// If this Fq element is part of a compressed point, the flag that indicates the sign of the
/// y coordinate is also returned.
pub(crate) fn deserialize_with_flags(buf: &[u8]) -> Result<(Fq, CompressedPointFlag), Error> {
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
pub(crate) fn unchecked_compressed_x_to_g1_point(buf: &[u8]) -> Result<AffineG1, Error> {
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
pub(crate) fn uncompressed_bytes_to_g1_point(buf: &[u8]) -> Result<AffineG1, Error> {
    if buf.len() != 64 {
        return Err(Error::InvalidXLength);
    };

    let (x_bytes, y_bytes) = buf.split_at(32);

    let x = Fq::from_slice(x_bytes).map_err(Error::Field)?;
    let y = Fq::from_slice(y_bytes).map_err(Error::Field)?;
    AffineG1::new(x, y).map_err(Error::Group)
}

/// Converts a compressed G2 point to an AffineG2 point.
///
/// Asserts that the compressed point is represented as a single fq2 element: the x coordinate
/// of the point.
/// Then, gets the y coordinate from the x coordinate.
/// For efficiency, this function does not check that the final point is on the curve.
pub(crate) fn unchecked_compressed_x_to_g2_point(buf: &[u8]) -> Result<AffineG2, Error> {
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
pub(crate) fn uncompressed_bytes_to_g2_point(buf: &[u8]) -> Result<AffineG2, Error> {
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
