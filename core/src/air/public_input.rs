use core::fmt::Debug;

use std::{array::IntoIter, ops::Index};

use p3_field::Field;
use serde::{Deserialize, Serialize};

use super::Word;

// TODO:  Create a config struct that will store the num_words setting and the hash function
//        and initial entropy used.
const PI_DIGEST_NUM_WORDS: usize = 8;

/// The PiDigest struct is used to represent the public input digest.  This is the hash of all the
/// bytes that the guest program has written to public input.
#[derive(Serialize, Deserialize, Clone, Copy, Default, Debug)]
pub struct PiDigest<T>(pub [T; PI_DIGEST_NUM_WORDS]);

/// Convertion from a byte array into a PiDigest<u32>.
impl From<&[u8]> for PiDigest<u32> {
    fn from(bytes: &[u8]) -> Self {
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
}

/// Create a PiDigest with u32 words to one with Word<T> words.
impl<T: Field> PiDigest<Word<T>> {
    pub fn new(orig: PiDigest<u32>) -> Self {
        PiDigest(orig.0.map(|x| x.into()))
    }
}

/// Implement the Index trait for PiDigest to index specific words.
impl<T> Index<usize> for PiDigest<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

/// Implement the IntoIterator trait for PiDigest to iterate over the words.
impl<T> IntoIterator for PiDigest<T> {
    type Item = T;
    type IntoIter = IntoIter<T, PI_DIGEST_NUM_WORDS>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Convertion into a byte vec
impl From<PiDigest<u32>> for Vec<u8> {
    fn from(val: PiDigest<u32>) -> Self {
        val.0
            .iter()
            .flat_map(|word| word.to_le_bytes().to_vec())
            .collect::<Vec<u8>>()
    }
}

/// Convertion into a field vec
impl<T: Debug + Copy> From<PiDigest<Word<T>>> for Vec<T> {
    fn from(val: PiDigest<Word<T>>) -> Self {
        val.0.iter().flat_map(|word| word.0).collect::<Vec<T>>()
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
