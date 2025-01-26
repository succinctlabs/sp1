use sha2::{Digest, Sha256};

pub trait AsLittleEndianBytes {
    fn to_little_endian(self) -> Self;
}

impl<const N: usize> AsLittleEndianBytes for [u8; N] {
    fn to_little_endian(mut self) -> Self {
        self.reverse();
        self
    }
}

pub fn sha256_hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
