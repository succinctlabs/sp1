use core::fmt::Debug;
use serde::{Deserialize, Serialize};

use super::Word;

// TODO:  Create a config struct that will store the num_words setting and the hash function
//        and initial entropy used.
const PV_DIGEST_NUM_WORDS: usize = 8;

/// The PublicValues struct is used to represent the public values digest.  This is the hash of all the
/// bytes that the guest program has written to public values.
#[derive(Serialize, Deserialize, Clone, Copy, Default, Debug)]
pub struct PublicValues<T> {
    committed_value_digest: [Word<T>; PV_DIGEST_NUM_WORDS],
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
