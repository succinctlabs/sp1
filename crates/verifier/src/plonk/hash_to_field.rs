use alloc::{vec, vec::Vec};
use core::hash::Hasher;
use sha2::Digest;

use crate::PlonkError;

pub(crate) struct WrappedHashToField {
    domain: Vec<u8>,
    to_hash: Vec<u8>,
}

impl WrappedHashToField {
    // Creates a new instance with a domain separator
    pub(crate) fn new(domain_separator: &[u8]) -> Result<Self, PlonkError> {
        Ok(Self { domain: domain_separator.to_vec(), to_hash: Vec::new() })
    }

    // Hashes the bytes to a field element and returns the byte representation
    pub(crate) fn sum(&self) -> Result<Vec<u8>, PlonkError> {
        let res = Self::hash(self.to_hash.clone(), self.domain.clone(), 1)?;

        Ok(res[0].clone())
    }

    pub(crate) fn hash(
        msg: Vec<u8>,
        dst: Vec<u8>,
        count: usize,
    ) -> Result<Vec<Vec<u8>>, PlonkError> {
        let bytes = 32;
        let l = 16 + bytes;

        let len_in_bytes = count * l;
        let pseudo_random_bytes = Self::expand_msg_xmd(msg, dst, len_in_bytes).unwrap();

        let mut res = Vec::new();
        for i in 0..count {
            res.push(pseudo_random_bytes[i * l..(i + 1) * l].to_vec());
        }

        Ok(res)
    }

    fn expand_msg_xmd(msg: Vec<u8>, dst: Vec<u8>, len: usize) -> Result<Vec<u8>, PlonkError> {
        let mut h = sha2::Sha256::new();

        let ell = len.div_ceil(32);

        if ell > 255 {
            Err(PlonkError::EllTooLarge)?;
        }
        if dst.len() > 255 {
            Err(PlonkError::DSTTooLarge)?;
        }

        let size_domain = dst.len();

        h.reset();

        // b_0 = H(msg_prime)
        h.update([0u8; 64]); // Assuming the block size is 64 bytes for SHA-256
        h.update(&msg);
        h.update([(len >> 8) as u8, len as u8, 0]);
        h.update(&dst);
        h.update([size_domain as u8]);
        let b0 = h.finalize_reset();

        // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
        h.update(b0);
        h.update([1]); // I2OSP(1, 1)
        h.update(&dst);
        h.update([size_domain as u8]);
        let mut b1 = h.finalize_reset();

        let mut res = vec![0u8; len];
        res[..32].copy_from_slice(&b1);

        for i in 2..=ell {
            h.reset();
            let mut strxor = vec![0u8; 32];
            for (j, (b0_byte, b1_byte)) in b0.iter().zip(b1.iter()).enumerate() {
                strxor[j] = b0_byte ^ b1_byte;
            }
            h.update(&strxor);
            h.update([i as u8]);
            h.update(&dst);
            h.update([size_domain as u8]);
            b1 = h.finalize_reset();

            let start = 32 * (i - 1);
            let end = core::cmp::min(start + 32, res.len());
            res[start..end].copy_from_slice(&b1[..end - start]);
        }

        Ok(res)
    }
}

impl Hasher for WrappedHashToField {
    fn finish(&self) -> u64 {
        // This method is not directly applicable to field elements, so it's a stub
        unimplemented!();
    }

    fn write(&mut self, bytes: &[u8]) {
        self.to_hash.extend_from_slice(bytes);
    }
}

impl Default for WrappedHashToField {
    fn default() -> Self {
        Self::new(&[]).unwrap()
    }
}

impl WrappedHashToField {
    // Resets the state of the hasher
    pub(crate) fn reset(&mut self) {
        self.to_hash.clear();
    }
}
