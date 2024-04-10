use crate::stark::PROOF_MAX_NUM_PVS;

use super::Word;
use core::fmt::Debug;
use itertools::Itertools;
use p3_field::{AbstractField, PrimeField32};
use serde::{Deserialize, Serialize};
use std::iter::once;

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

impl PublicValues<u32, u32> {
    /// Convert the public values into a vector of field elements.  This function will pad the vector
    /// to the maximum number of public values.
    pub fn to_vec<F: AbstractField>(&self) -> Vec<F> {
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
            ret.len() <= PROOF_MAX_NUM_PVS,
            "Too many public values: {}",
            ret.len()
        );

        ret.resize(PROOF_MAX_NUM_PVS, F::zero());

        ret
    }
}

impl<F: PrimeField32> PublicValues<Word<F>, F> {
    /// Convert a vector of field elements into a PublicValues struct.
    pub fn from_vec(data: Vec<T>) -> Self {
        let mut iter = data.iter().cloned();

        let mut committed_value_digest = Vec::new();
        for _ in 0..PV_DIGEST_NUM_WORDS {
            committed_value_digest.push(Word::from_iter(&mut iter));
        }

        // Collecting the remaining items into a tuple.  Note that it is only getting the first
        // four items, as the rest would be padded values.
        let remaining_items = iter.collect_vec().as_slice()[..4];

        if let [shard, first_row_pc, last_row_next_pc, exit_code] = &remaining_items {
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

    /// Retrieve the commitment digest from a serialized PublicValues struct.
    pub fn deserialize_commitment_digest(data: Vec<F>) -> Vec<u8> {
        let serialized_pv = PublicValues::<Word<F>, F>::from_vec(data);
        serialized_pv
            .committed_value_digest
            .into_iter()
            .flat_map(|w| w.0.map(|x| F::as_canonical_u32(&x) as u8))
            .collect_vec()
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
