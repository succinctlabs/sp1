use std::{array::IntoIter, ops::Index};

use serde::{Deserialize, Serialize};

const PI_DIGEST_NUM_WORDS: usize = 8;

#[derive(Serialize, Deserialize, Clone, Copy, Default)]
pub struct PiDigest<T>(pub [T; PI_DIGEST_NUM_WORDS]);

impl<T> Index<usize> for PiDigest<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<T> IntoIterator for PiDigest<T> {
    type Item = T;
    type IntoIter = IntoIter<T, PI_DIGEST_NUM_WORDS>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl PiDigest<u32> {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        const WORD_SIZE: usize = 4;

        assert!(bytes.len() == PI_DIGEST_NUM_WORDS * WORD_SIZE);

        let mut words = [0u32; PI_DIGEST_NUM_WORDS];
        for i in 0..PI_DIGEST_NUM_WORDS {
            words[i] = u32::from_le_bytes(
                bytes[i * WORD_SIZE..(i + 1) * WORD_SIZE]
                    .try_into()
                    .unwrap(),
            );
        }
        Self(words)
    }

    pub fn empty() -> Self {
        Self([0; PI_DIGEST_NUM_WORDS])
    }
}

impl<T: From<u32>> PiDigest<T> {
    pub fn new(orig: PiDigest<u32>) -> Self {
        PiDigest(orig.0.map(|x| x.into()))
    }
}

#[cfg(test)]
mod tests {

    #[test]
    /// Check that the PI_DIGEST_NUM_WORDS number match the zkVM crate's.
    fn test_pi_digest_num_words_consistency_zkvm() {
        assert_eq!(super::PI_DIGEST_NUM_WORDS, sp1_zkvm::PI_DIGEST_NUM_WORDS);
    }
}
