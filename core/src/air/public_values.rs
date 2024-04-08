use core::fmt::Debug;
use itertools::Itertools;
use p3_field::AbstractField;
use serde::{Deserialize, Serialize};
use std::iter::once;

use super::Word;

pub const PV_DIGEST_NUM_WORDS: usize = 8;

/// The PublicValues struct is used to store all of a shard proof's public values.
#[derive(Serialize, Deserialize, Clone, Copy, Default, Debug)]
pub struct PublicValues<T> {
    /// The hash of all the bytes that the guest program has written to public values.
    pub committed_value_digest: [Word<T>; PV_DIGEST_NUM_WORDS],

    /// The shard number.
    pub shard: T,

    /// The shard's start program counter.
    pub start_pc: T,

    /// The expected start program counter for the next shard.
    pub next_pc: T,

    /// The exit code of the program.  Only valid if halt has been executed.
    pub exit_code: T,
}

impl<F: AbstractField> PublicValues<F> {
    pub fn from_u32(other: PublicValues<u32>) -> Self {
        let PublicValues {
            committed_value_digest,
            shard,
            start_pc: first_row_pc,
            next_pc: last_row_next_pc,
            exit_code,
        } = other;
        Self {
            committed_value_digest: committed_value_digest.map(|w| {
                Word([
                    F::from_canonical_u32(w.0[0]),
                    F::from_canonical_u32(w.0[1]),
                    F::from_canonical_u32(w.0[2]),
                    F::from_canonical_u32(w.0[3]),
                ])
            }),
            shard: F::from_canonical_u32(shard),
            start_pc: F::from_canonical_u32(first_row_pc),
            next_pc: F::from_canonical_u32(last_row_next_pc),
            exit_code: F::from_canonical_u32(exit_code),
        }
    }
}

impl<T: Clone + Debug> PublicValues<T> {
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
        if let [shard, first_row_pc, last_row_next_pc, exit_code] =
            iter.collect::<Vec<_>>().as_slice()
        {
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
