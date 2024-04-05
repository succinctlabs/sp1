use core::fmt::Debug;
use itertools::Itertools;
use p3_field::AbstractField;
use serde::{Deserialize, Serialize};
use std::iter::once;

use super::Word;

pub const PV_DIGEST_NUM_WORDS: usize = 8;

/// The PublicValues struct is used to store all of a shard proof's public values.
#[derive(Serialize, Deserialize, Clone, Copy, Default, Debug)]
pub struct PublicValues<W, T> {
    /// The hash of all the bytes that the guest program has written to public values.
    pub committed_value_digest: [W; PV_DIGEST_NUM_WORDS],

    /// The shard number.
    pub shard: T,

    /// The first row's program counter.
    pub first_row_pc: T,

    /// The last row's expected next program counter.
    pub last_row_next_pc: T,

    /// Flag indicating whether the last instruction was a halt.
    pub last_instr_halt: T,

    /// The exit code of the program.  Only valid if halt has been executed.
    pub exit_code: T,
}

impl<F: AbstractField> PublicValues<Word<F>, F> {
    pub fn new(other: PublicValues<u32, u32>) -> Self {
        let PublicValues {
            committed_value_digest,
            shard,
            first_row_pc,
            last_row_next_pc,
            last_instr_halt,
            exit_code,
        } = other;
        Self {
            committed_value_digest: committed_value_digest.map(Word::from),
            shard: F::from_canonical_u32(shard),
            first_row_pc: F::from_canonical_u32(first_row_pc),
            last_row_next_pc: F::from_canonical_u32(last_row_next_pc),
            last_instr_halt: F::from_canonical_u32(last_instr_halt),
            exit_code: F::from_canonical_u32(exit_code),
        }
    }

    pub fn to_vec(&self) -> Vec<F> {
        self.committed_value_digest
            .iter()
            .flat_map(|w| w.clone().into_iter())
            .chain(once(self.shard.clone()))
            .chain(once(self.first_row_pc.clone()))
            .chain(once(self.last_row_next_pc.clone()))
            .chain(once(self.last_instr_halt.clone()))
            .chain(once(self.exit_code.clone()))
            .collect_vec()
    }

    pub fn from_vec(data: Vec<F>) -> Self {
        let mut iter = data.iter().cloned();

        let mut committed_value_digest = Vec::new();
        for _ in 0..PV_DIGEST_NUM_WORDS {
            committed_value_digest.push(Word::from_iter(&mut iter));
        }

        // Collecting the remaining items into a tuple.
        if let [shard, first_row_pc, last_row_next_pc, last_instr_halt, exit_code] =
            iter.collect::<Vec<_>>().as_slice()
        {
            Self {
                committed_value_digest: committed_value_digest.try_into().unwrap(),
                shard: shard.to_owned(),
                first_row_pc: first_row_pc.to_owned(),
                last_row_next_pc: last_row_next_pc.to_owned(),
                last_instr_halt: last_instr_halt.to_owned(),
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
