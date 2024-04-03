use core::fmt::Debug;
use itertools::Itertools;
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
    shard: T,
    first_row_clk: T,
    last_row_clk: T,
    last_row_next_clk: T,
    first_row_pc: T,
    last_row_pc: T,
    last_row_next_pc: T,
    last_row_is_halt: T,
    exit_code: T,
}

impl<T> PublicValues<Word<T>, T> {
    pub fn serialize(&self) -> &[T] {
        self.committed_value_digest
            .iter()
            .flat_map(|w| w.into_iter())
            .chain(once(self.shard))
            .chain(once(self.first_row_clk))
            .chain(once(self.last_row_clk))
            .chain(once(self.last_row_next_clk))
            .chain(once(self.first_row_pc))
            .chain(once(self.last_row_pc))
            .chain(once(self.last_row_next_pc))
            .chain(once(self.last_row_is_halt))
            .chain(once(self.exit_code))
            .collect_vec()
            .as_slice()
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
