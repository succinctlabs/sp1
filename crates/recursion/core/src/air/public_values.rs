use crate::runtime::{DIGEST_SIZE, HASH_RATE, PERMUTATION_WIDTH};

use core::fmt::Debug;
use p3_challenger::DuplexChallenger;
use p3_field::PrimeField32;
use p3_symmetric::CryptographicPermutation;
use serde::{Deserialize, Serialize};
use sp1_core_machine::utils::indices_arr;
use sp1_derive::AlignedBorrow;
use sp1_stark::{air::POSEIDON_NUM_WORDS, septic_digest::SepticDigest, Word, PROOF_MAX_NUM_PVS};
use static_assertions::const_assert_eq;
use std::mem::{size_of, transmute};

pub const PV_DIGEST_NUM_WORDS: usize = 8;

pub const CHALLENGER_STATE_NUM_ELTS: usize = size_of::<ChallengerPublicValues<u8>>();

pub const RECURSIVE_PROOF_NUM_PV_ELTS: usize = size_of::<RecursionPublicValues<u8>>();

const fn make_col_map() -> RecursionPublicValues<usize> {
    let indices_arr = indices_arr::<RECURSIVE_PROOF_NUM_PV_ELTS>();
    unsafe {
        transmute::<[usize; RECURSIVE_PROOF_NUM_PV_ELTS], RecursionPublicValues<usize>>(indices_arr)
    }
}

pub const RECURSION_PUBLIC_VALUES_COL_MAP: RecursionPublicValues<usize> = make_col_map();

// All the fields before `digest` are hashed to produce the digest.
pub const NUM_PV_ELMS_TO_HASH: usize = RECURSION_PUBLIC_VALUES_COL_MAP.digest[0];

// Recursive proof has more public values than core proof, so the max number constant defined in
// sp1_core should be set to `RECURSIVE_PROOF_NUM_PV_ELTS`.
const_assert_eq!(RECURSIVE_PROOF_NUM_PV_ELTS, PROOF_MAX_NUM_PVS);

#[derive(AlignedBorrow, Serialize, Deserialize, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct ChallengerPublicValues<T> {
    pub sponge_state: [T; PERMUTATION_WIDTH],
    pub num_inputs: T,
    pub input_buffer: [T; PERMUTATION_WIDTH],
    pub num_outputs: T,
    pub output_buffer: [T; PERMUTATION_WIDTH],
}

impl<T: Clone> ChallengerPublicValues<T> {
    pub fn set_challenger<P: CryptographicPermutation<[T; PERMUTATION_WIDTH]>>(
        &self,
        challenger: &mut DuplexChallenger<T, P, PERMUTATION_WIDTH, HASH_RATE>,
    ) where
        T: PrimeField32,
    {
        challenger.sponge_state = self.sponge_state;
        let num_inputs = self.num_inputs.as_canonical_u32() as usize;
        challenger.input_buffer = self.input_buffer[..num_inputs].to_vec();
        let num_outputs = self.num_outputs.as_canonical_u32() as usize;
        challenger.output_buffer = self.output_buffer[..num_outputs].to_vec();
    }

    pub fn as_array(&self) -> [T; CHALLENGER_STATE_NUM_ELTS]
    where
        T: Copy,
    {
        unsafe { std::mem::transmute_copy(self) }
    }
}

/// The PublicValues struct is used to store all of a reduce proof's public values.
#[derive(AlignedBorrow, Serialize, Deserialize, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct RecursionPublicValues<T> {
    /// The hash of all the bytes that the program has written to public values.
    pub committed_value_digest: [Word<T>; PV_DIGEST_NUM_WORDS],

    /// The hash of all deferred proofs that have been witnessed in the VM.
    pub deferred_proofs_digest: [T; POSEIDON_NUM_WORDS],

    /// The start pc of shards being proven.
    pub start_pc: T,

    /// The expected start pc for the next shard.
    pub next_pc: T,

    /// First shard being proven.
    pub start_shard: T,

    /// Next shard that should be proven.
    pub next_shard: T,

    /// First execution shard being proven.
    pub start_execution_shard: T,

    /// Next execution shard that should be proven.
    pub next_execution_shard: T,

    /// Previous MemoryInit address bits.
    pub previous_init_addr_bits: [T; 32],

    /// Last MemoryInit address bits.
    pub last_init_addr_bits: [T; 32],

    /// Previous MemoryFinalize address bits.
    pub previous_finalize_addr_bits: [T; 32],

    /// Last MemoryFinalize address bits.
    pub last_finalize_addr_bits: [T; 32],

    /// Start state of reconstruct_deferred_digest.
    pub start_reconstruct_deferred_digest: [T; POSEIDON_NUM_WORDS],

    /// End state of reconstruct_deferred_digest.
    pub end_reconstruct_deferred_digest: [T; POSEIDON_NUM_WORDS],

    /// The commitment to the sp1 program being proven.
    pub sp1_vk_digest: [T; DIGEST_SIZE],

    /// The root of the vk merkle tree.
    pub vk_root: [T; DIGEST_SIZE],

    /// Current cumulative sum of lookup bus. Note that for recursive proofs for core proofs, this
    /// contains the global cumulative sum.
    pub global_cumulative_sum: SepticDigest<T>,

    /// Whether the proof completely proves the program execution.
    pub is_complete: T,

    /// Whether the proof represents a collection of shards which contain at least one execution
    /// shard, i.e. a shard that contains the `cpu` chip.
    pub contains_execution_shard: T,

    /// The exit code of the program.
    pub exit_code: T,

    /// The digest of all the previous public values elements.
    pub digest: [T; DIGEST_SIZE],
}

/// Converts the public values to an array of elements.
impl<F: Copy> RecursionPublicValues<F> {
    pub fn as_array(&self) -> [F; RECURSIVE_PROOF_NUM_PV_ELTS] {
        unsafe { std::mem::transmute_copy(self) }
    }
}

impl<T: Copy> IntoIterator for RecursionPublicValues<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, RECURSIVE_PROOF_NUM_PV_ELTS>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_array().into_iter()
    }
}

impl<T: Copy> IntoIterator for ChallengerPublicValues<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, CHALLENGER_STATE_NUM_ELTS>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_array().into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recursion_public_values_as_array() {
        // Create a sample RecursionPublicValues with arbitrary values.
        let test_values = RecursionPublicValues {
            committed_value_digest: [Word([1, 2, 3, 4]); PV_DIGEST_NUM_WORDS],
            deferred_proofs_digest: [2; POSEIDON_NUM_WORDS],
            start_pc: 3,
            next_pc: 4,
            start_shard: 5,
            next_shard: 6,
            start_execution_shard: 7,
            next_execution_shard: 8,
            previous_init_addr_bits: [9; 32],
            last_init_addr_bits: [10; 32],
            previous_finalize_addr_bits: [11; 32],
            last_finalize_addr_bits: [12; 32],
            start_reconstruct_deferred_digest: [13; POSEIDON_NUM_WORDS],
            end_reconstruct_deferred_digest: [14; POSEIDON_NUM_WORDS],
            sp1_vk_digest: [15; DIGEST_SIZE],
            vk_root: [16; DIGEST_SIZE],
            global_cumulative_sum: Default::default(),
            is_complete: 18,
            contains_execution_shard: 19,
            exit_code: 20,
            digest: [21; DIGEST_SIZE],
        };

        // Convert to array and verify the array length.
        let as_array = test_values.as_array();
        assert_eq!(as_array.len(), RECURSIVE_PROOF_NUM_PV_ELTS);

        // Verify specific elements in the array (by index, depending on layout).
        for i in 0..PV_DIGEST_NUM_WORDS {
            assert_eq!(as_array[4 * i + 0], 1);
            assert_eq!(as_array[4 * i + 1], 2);
            assert_eq!(as_array[4 * i + 2], 3);
            assert_eq!(as_array[4 * i + 3], 4);
        }

        // Verify deferred_proofs_digest.
        let mut index = 4 * PV_DIGEST_NUM_WORDS;
        for &value in &test_values.deferred_proofs_digest {
            assert_eq!(as_array[index], value);
            index += 1;
        }

        // Verify scalar fields.
        assert_eq!(as_array[index], test_values.start_pc);
        index += 1;
        assert_eq!(as_array[index], test_values.next_pc);
        index += 1;
        assert_eq!(as_array[index], test_values.start_shard);
        index += 1;
        assert_eq!(as_array[index], test_values.next_shard);
        index += 1;
        assert_eq!(as_array[index], test_values.start_execution_shard);
        index += 1;
        assert_eq!(as_array[index], test_values.next_execution_shard);
        index += 1;

        // Verify previous_init_addr_bits.
        for &value in &test_values.previous_init_addr_bits {
            assert_eq!(as_array[index], value);
            index += 1;
        }

        // Verify last_init_addr_bits.
        for &value in &test_values.last_init_addr_bits {
            assert_eq!(as_array[index], value);
            index += 1;
        }

        // Verify previous_finalize_addr_bits.
        for &value in &test_values.previous_finalize_addr_bits {
            assert_eq!(as_array[index], value);
            index += 1;
        }

        // Verify last_finalize_addr_bits.
        for &value in &test_values.last_finalize_addr_bits {
            assert_eq!(as_array[index], value);
            index += 1;
        }

        // Verify start_reconstruct_deferred_digest.
        for &value in &test_values.start_reconstruct_deferred_digest {
            assert_eq!(as_array[index], value);
            index += 1;
        }

        // Verify end_reconstruct_deferred_digest.
        for &value in &test_values.end_reconstruct_deferred_digest {
            assert_eq!(as_array[index], value);
            index += 1;
        }

        // Verify sp1_vk_digest.
        for &value in &test_values.sp1_vk_digest {
            assert_eq!(as_array[index], value);
            index += 1;
        }

        // Verify vk_root.
        for &value in &test_values.vk_root {
            assert_eq!(as_array[index], value);
            index += 1;
        }

        // Verify global_cumulative_sum (default is [0; DIGEST_SIZE]).
        for &value in &test_values.global_cumulative_sum.0.x.0 {
            assert_eq!(as_array[index], value);
            index += 1;
        }

        for &value in &test_values.global_cumulative_sum.0.y.0 {
            assert_eq!(as_array[index], value);
            index += 1;
        }

        // Verify is_complete.
        assert_eq!(as_array[index], test_values.is_complete);
        index += 1;

        // Verify contains_execution_shard.
        assert_eq!(as_array[index], test_values.contains_execution_shard);
        index += 1;

        // Verify exit_code.
        assert_eq!(as_array[index], test_values.exit_code);
        index += 1;

        // Verify digest.
        for &value in &test_values.digest {
            assert_eq!(as_array[index], value);
            index += 1;
        }

        // Verify the final index of the array.
        assert_eq!(index, RECURSIVE_PROOF_NUM_PV_ELTS);
    }

    #[test]
    fn test_challenger_public_values_as_array() {
        // Create a sample ChallengerPublicValues with arbitrary values.
        let test_values = ChallengerPublicValues {
            sponge_state: [1; PERMUTATION_WIDTH],
            num_inputs: 2,
            input_buffer: [3; PERMUTATION_WIDTH],
            num_outputs: 4,
            output_buffer: [5; PERMUTATION_WIDTH],
        };

        // Convert to array and verify the array length.
        let as_array = test_values.as_array();
        assert_eq!(as_array.len(), CHALLENGER_STATE_NUM_ELTS);

        // Verify sponge_state.
        let mut index = 0;
        for &value in &test_values.sponge_state {
            assert_eq!(as_array[index], value);
            index += 1;
        }

        // Verify num_inputs.
        assert_eq!(as_array[index], test_values.num_inputs);
        index += 1;

        // Verify input_buffer.
        for &value in &test_values.input_buffer {
            assert_eq!(as_array[index], value);
            index += 1;
        }

        // Verify num_outputs.
        assert_eq!(as_array[index], test_values.num_outputs);
        index += 1;

        // Verify output_buffer.
        for &value in &test_values.output_buffer {
            assert_eq!(as_array[index], value);
            index += 1;
        }

        // Verify the final index of the array.
        assert_eq!(index, CHALLENGER_STATE_NUM_ELTS);
    }
}
