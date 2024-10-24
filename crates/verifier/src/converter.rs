use core::cmp::Ordering;

use bn::{AffineG1, AffineG2, Fq, Fq2};

use crate::{
    constants::{CompressedPointFlag, MASK},
    error::Error,
};

pub(crate) fn is_zeroed(first_byte: u8, buf: &[u8]) -> Result<bool, Error> {
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

pub(crate) fn deserialize_with_flags(buf: &[u8]) -> Result<(Fq, CompressedPointFlag), Error> {
    if buf.len() != 32 {
        return Err(Error::InvalidXLength);
    };

    let m_data = buf[0] & MASK;
    if m_data == u8::from(CompressedPointFlag::Infinity) {
        if !is_zeroed(buf[0] & !MASK, &buf[1..32]).map_err(|_| Error::InvalidPoint)? {
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

pub(crate) fn uncompressed_bytes_to_g1_point(buf: &[u8]) -> Result<AffineG1, Error> {
    if buf.len() != 64 {
        return Err(Error::InvalidXLength);
    };

    let (x_bytes, y_bytes) = buf.split_at(32);

    let x = Fq::from_slice(x_bytes).map_err(Error::Field)?;
    let y = Fq::from_slice(y_bytes).map_err(Error::Field)?;
    AffineG1::new(x, y).map_err(Error::Group)
}

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
