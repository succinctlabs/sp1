use crate::runtime::{DIGEST_SIZE, HASH_RATE, PERMUTATION_WIDTH};

use core::fmt::Debug;
use p3_challenger::DuplexChallenger;
use p3_field::PrimeField32;
use p3_symmetric::CryptographicPermutation;
use serde::{Deserialize, Serialize};
use sp1_core::{
    air::{Word, POSEIDON_NUM_WORDS},
    stark::PROOF_MAX_NUM_PVS,
    utils::indices_arr,
};
use sp1_derive::AlignedBorrow;
use static_assertions::const_assert_eq;
use std::mem::{size_of, transmute};

pub const PV_DIGEST_NUM_WORDS: usize = 8;

pub const CHALLENGER_STATE_NUM_ELTS: usize = 50;

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

impl<T: Clone + Debug> ChallengerPublicValues<T> {
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

    /// Start state of reconstruct_challenger.
    pub start_reconstruct_challenger: ChallengerPublicValues<T>,

    /// End state of reconstruct_challenger.
    pub end_reconstruct_challenger: ChallengerPublicValues<T>,

    /// Start state of reconstruct_deferred_digest.
    pub start_reconstruct_deferred_digest: [T; POSEIDON_NUM_WORDS],

    /// End state of reconstruct_deferred_digest.
    pub end_reconstruct_deferred_digest: [T; POSEIDON_NUM_WORDS],

    /// The commitment to the sp1 program being proven.
    pub sp1_vk_digest: [T; DIGEST_SIZE],

    /// The commitment to the compress key being used in recursive verification.
    pub compress_vk_digest: [T; DIGEST_SIZE],

    /// The leaf challenger containing the entropy from the main trace commitment.
    pub leaf_challenger: ChallengerPublicValues<T>,

    /// Current cumulative sum of lookup bus.
    pub cumulative_sum: [T; 4],

    /// Whether the proof completely proves the program execution.
    pub is_complete: T,

    /// The digest of all the previous public values elements.
    pub digest: [T; DIGEST_SIZE],

    /// The exit code of the program.  Note that this is not part of the public values digest, since
    /// it's value will be individually constrained.
    pub exit_code: T,
}
