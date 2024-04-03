use core::fmt::Debug;
use itertools::Itertools;
use p3_field::AbstractField;
use serde::{Deserialize, Serialize};
use std::iter::once;

use super::Word;

// TODO:  Create a config struct that will store the num_words setting and the hash function
//        and initial entropy used.
const PV_DIGEST_NUM_WORDS: usize = 8;

/// The PublicValues struct is used to represent the public values digest.  This is the hash of all the
/// bytes that the guest program has written to public values.
#[derive(Serialize, Deserialize, Clone, Copy, Default, Debug)]
pub struct PublicValues<W, T> {
    pub committed_value_digest: [W; PV_DIGEST_NUM_WORDS],
    pub shard: T,
    pub first_row_clk: T,
    pub last_row_next_clk: T,
    pub first_row_pc: T,
    pub last_row_next_pc: T,
    pub exit_code: T,
}

impl<F: AbstractField> PublicValues<Word<F>, F> {
    pub fn new(other: PublicValues<u32, u32>) -> Self {
        let PublicValues {
            committed_value_digest,
            shard,
            first_row_clk,
            last_row_next_clk,
            first_row_pc,
            last_row_next_pc,
            exit_code,
        } = other;
        Self {
            committed_value_digest: committed_value_digest.map(Word::from),
            shard: F::from_canonical_u32(shard),
            first_row_clk: F::from_canonical_u32(first_row_clk),
            last_row_next_clk: F::from_canonical_u32(last_row_next_clk),
            first_row_pc: F::from_canonical_u32(first_row_pc),
            last_row_next_pc: F::from_canonical_u32(last_row_next_pc),
            exit_code: F::from_canonical_u32(exit_code),
        }
    }

    pub fn serialize(&self) -> Vec<F> {
        self.committed_value_digest
            .iter()
            .flat_map(|w| w.clone().into_iter())
            .chain(once(self.shard.clone()))
            .chain(once(self.first_row_clk.clone()))
            .chain(once(self.last_row_next_clk.clone()))
            .chain(once(self.first_row_pc.clone()))
            .chain(once(self.last_row_next_pc.clone()))
            .chain(once(self.exit_code.clone()))
            .collect_vec()
    }

    pub fn deserialize(data: &[F]) -> Self {
        let mut iter = data.iter().cloned();
        let mut committed_value_digest: [Word<F>; PV_DIGEST_NUM_WORDS] = Default::default();
        for w in committed_value_digest.iter_mut() {
            *w = Word::from_iter(&mut iter);
        }
        let shard = iter.next().unwrap().clone();
        let first_row_clk = iter.next().unwrap().clone();
        let last_row_next_clk = iter.next().unwrap().clone();
        let first_row_pc = iter.next().unwrap().clone();
        let last_row_next_pc = iter.next().unwrap().clone();
        let exit_code = iter.next().unwrap().clone();
        Self {
            committed_value_digest,
            shard,
            first_row_clk,
            last_row_next_clk,
            first_row_pc,
            last_row_next_pc,
            exit_code,
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
