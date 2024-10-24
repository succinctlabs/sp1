/// Gnark (and arkworks) use the 2 most significant bits to encode the flag for a compressed point.
pub(crate) const MASK: u8 = 0b11 << 6;

/// The flags for a positive, negative, or infinity compressed point.
pub(crate) const COMPRESSED_POSITIVE: u8 = 0b10 << 6;
pub(crate) const COMPRESSED_NEGATIVE: u8 = 0b11 << 6;
pub(crate) const COMPRESSED_INFINITY: u8 = 0b01 << 6;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompressedPointFlag {
    Positive = COMPRESSED_POSITIVE as isize,
    Negative = COMPRESSED_NEGATIVE as isize,
    Infinity = COMPRESSED_INFINITY as isize,
}

impl From<u8> for CompressedPointFlag {
    fn from(val: u8) -> Self {
        match val {
            COMPRESSED_POSITIVE => CompressedPointFlag::Positive,
            COMPRESSED_NEGATIVE => CompressedPointFlag::Negative,
            COMPRESSED_INFINITY => CompressedPointFlag::Infinity,
            _ => panic!("Invalid compressed point flag"),
        }
    }
}

impl From<CompressedPointFlag> for u8 {
    fn from(value: CompressedPointFlag) -> Self {
        value as u8
    }
}
