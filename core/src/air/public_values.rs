use core::fmt::Debug;
use core::mem::size_of;
use std::array;
use std::iter::once;

use itertools::Itertools;
use p3_field::{AbstractField, PrimeField32};
use serde::{Deserialize, Serialize};

use super::Word;
use crate::stark::PROOF_MAX_NUM_PVS;

/// The number of non padded elements in the SP1 proofs public values vec.
pub const SP1_PROOF_NUM_PV_ELTS: usize = size_of::<PublicValues<Word<u8>, u8>>();

/// The number of 32 bit words in the SP1 proof's commited value digest.
pub const PV_DIGEST_NUM_WORDS: usize = 8;

pub const POSEIDON_NUM_WORDS: usize = 8;

/// The PublicValues struct is used to store all of a shard proof's public values.
#[derive(Serialize, Deserialize, Clone, Copy, Default, Debug)]
pub struct PublicValues<W, T> {
    /// The hash of all the bytes that the guest program has written to public values.
    pub committed_value_digest: [W; PV_DIGEST_NUM_WORDS],

    /// The hash of all deferred proofs that have been witnessed in the VM. It will be rebuilt in
    /// recursive verification as the proofs get verified. The hash itself is a rolling poseidon2
    /// hash of each proof+vkey hash and the previous hash which is initially zero.
    pub deferred_proofs_digest: [T; POSEIDON_NUM_WORDS],

    /// The shard's start program counter.
    pub start_pc: T,

    /// The expected start program counter for the next shard.
    pub next_pc: T,

    /// The exit code of the program.  Only valid if halt has been executed.
    pub exit_code: T,

    /// The shard number.
    pub shard: T,
}

impl PublicValues<u32, u32> {
    /// Convert the public values into a vector of field elements.  This function will pad the vector
    /// to the maximum number of public values.
    pub fn to_vec<F: AbstractField>(&self) -> Vec<F> {
        let mut ret = self
            .committed_value_digest
            .iter()
            .flat_map(|w| Word::<F>::from(*w).into_iter())
            .chain(
                self.deferred_proofs_digest
                    .iter()
                    .cloned()
                    .map(F::from_canonical_u32),
            )
            .chain(once(F::from_canonical_u32(self.start_pc)))
            .chain(once(F::from_canonical_u32(self.next_pc)))
            .chain(once(F::from_canonical_u32(self.exit_code)))
            .chain(once(F::from_canonical_u32(self.shard)))
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

impl<T: Clone + Debug> PublicValues<Word<T>, T> {
    /// Convert a vector of field elements into a PublicValues struct.
    pub fn from_vec(data: Vec<T>) -> Self {
        let mut iter = data.iter().cloned();

        let committed_value_digest = array::from_fn(|_| Word::from_iter(&mut iter));

        let deferred_proofs_digest = iter
            .by_ref()
            .take(POSEIDON_NUM_WORDS)
            .collect_vec()
            .try_into()
            .unwrap();

        // Collecting the remaining items into a tuple.  Note that it is only getting the first
        // four items, as the rest would be padded values.
        let remaining_items = iter.collect_vec();
        if remaining_items.len() < 4 {
            panic!("Invalid number of items in the serialized vector.");
        }

        let [start_pc, next_pc, exit_code, shard] = match &remaining_items.as_slice()[0..4] {
            [start_pc, next_pc, exit_code, shard] => [start_pc, next_pc, exit_code, shard],
            _ => unreachable!(),
        };

        Self {
            committed_value_digest,
            deferred_proofs_digest,
            start_pc: start_pc.to_owned(),
            next_pc: next_pc.to_owned(),
            exit_code: exit_code.to_owned(),
            shard: shard.to_owned(),
        }
    }
}

impl<F: PrimeField32> PublicValues<Word<F>, F> {
    /// Returns the commit digest as a vector of little-endian bytes.
    pub fn commit_digest_bytes(&self) -> Vec<u8> {
        self.committed_value_digest
            .iter()
            .flat_map(|w| w.into_iter().map(|f| f.as_canonical_u32() as u8))
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
