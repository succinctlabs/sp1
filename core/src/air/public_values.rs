use crate::stark::MAX_NUM_PUBLIC_VALUES;

use super::Word;
use core::fmt::Debug;
use itertools::Itertools;
use p3_field::{AbstractField, PrimeField32};
use serde::{Deserialize, Serialize};
use std::iter::once;

pub trait PubicValuesCommitDigest {
    fn deserialize_commitment_digest<T>(data: Vec<T>) -> Vec<u8>;
}

pub const PV_DIGEST_NUM_WORDS: usize = 8;

/// The PublicValues struct is used to store all of a shard proof's public values.
#[derive(Serialize, Deserialize, Clone, Copy, Default, Debug)]
pub struct PublicValues<W, T> {
    /// The hash of all the bytes that the guest program has written to public values.
    pub committed_value_digest: [W; PV_DIGEST_NUM_WORDS],

    /// The shard number.
    pub shard: T,

    /// The shard's start program counter.
    pub start_pc: T,

    /// The expected start program counter for the next shard.
    pub next_pc: T,

    /// The exit code of the program.  Only valid if halt has been executed.
    pub exit_code: T,
}

impl<F: PrimeField32> PublicValues<Word<F>, F> {
    pub fn deserialize_commitment_digest(data: Vec<F>) -> Vec<u8> {
        let serialized_pv = PublicValues::<Word<F>, F>::from_vec(data);
        serialized_pv
            .committed_value_digest
            .into_iter()
            .flat_map(|w| w.0.map(|x| F::as_canonical_u32(&x) as u8))
            .collect_vec()
    }
}

impl PublicValues<u32, u32> {
    pub fn to_field_elms<F: AbstractField>(&self) -> Vec<F> {
        let mut ret = self
            .committed_value_digest
            .iter()
            .flat_map(|w| Word::<F>::from(*w).into_iter())
            .chain(once(F::from_canonical_u32(self.shard)))
            .chain(once(F::from_canonical_u32(self.start_pc)))
            .chain(once(F::from_canonical_u32(self.next_pc)))
            .chain(once(F::from_canonical_u32(self.exit_code)))
            .collect_vec();

        assert!(
            ret.len() <= MAX_NUM_PUBLIC_VALUES,
            "Too many public values: {}",
            ret.len()
        );

        ret.resize(MAX_NUM_PUBLIC_VALUES, F::zero());

        ret
    }
}

impl<F: AbstractField> PublicValues<Word<F>, F> {
    pub fn new(other: PublicValues<u32, u32>) -> Self {
        let PublicValues {
            committed_value_digest,
            shard,
            start_pc: first_row_pc,
            next_pc: last_row_next_pc,
            exit_code,
        } = other;
        Self {
            committed_value_digest: committed_value_digest.map(Word::from),
            shard: F::from_canonical_u32(shard),
            start_pc: F::from_canonical_u32(first_row_pc),
            next_pc: F::from_canonical_u32(last_row_next_pc),
            exit_code: F::from_canonical_u32(exit_code),
        }
    }
}

impl<T: Clone + Debug> PublicValues<Word<T>, T> {
    pub fn to_vec(&self) -> Vec<T> {
        self.committed_value_digest
            .iter()
            .flat_map(|w| w.clone().into_iter())
            .chain(once(self.shard.clone()))
            .chain(once(self.start_pc.clone()))
            .chain(once(self.next_pc.clone()))
            .chain(once(self.exit_code.clone()))
            .collect_vec()
    }

    pub fn from_vec(data: Vec<T>) -> Self {
        let mut iter = data.iter().cloned();

        let mut committed_value_digest = Vec::new();
        for _ in 0..PV_DIGEST_NUM_WORDS {
            committed_value_digest.push(Word::from_iter(&mut iter));
        }

        // Collecting the remaining items into a tuple.
        let binding = iter.collect_vec();
        let remaining_items = binding.as_slice();

        if let [shard, first_row_pc, last_row_next_pc, exit_code] = &remaining_items[..4] {
            Self {
                committed_value_digest: committed_value_digest.try_into().unwrap(),
                shard: shard.to_owned(),
                start_pc: first_row_pc.to_owned(),
                next_pc: last_row_next_pc.to_owned(),
                exit_code: exit_code.to_owned(),
            }
        } else {
            panic!("Invalid number of items in the serialized vector.");
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::air::public_values;

    /// Check that the PI_DIGEST_NUM_WORDS number match the zkVM crate's.
    #[test]
    fn test_public_values_digest_num_words_consistency_zkvm() {
        assert_eq!(
            public_values::PV_DIGEST_NUM_WORDS,
            sp1_zkvm::PV_DIGEST_NUM_WORDS
        );
    }
}
