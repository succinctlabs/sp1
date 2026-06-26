use crate::{DIGEST_SIZE, PERMUTATION_WIDTH};
use core::fmt::Debug;
use serde::{Deserialize, Serialize};
use slop_algebra::PrimeField32;
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{timestamp_from_limbs, ShardRange, POSEIDON_NUM_WORDS, PROOF_NONCE_NUM_WORDS},
    indices_arr, PROOF_MAX_NUM_PVS,
};
use static_assertions::const_assert_eq;
use std::{
    borrow::BorrowMut,
    mem::{size_of, transmute, MaybeUninit},
};

pub const PV_DIGEST_NUM_WORDS: usize = 8;

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

/// The PublicValues struct is used to store all of a recursion proof's public values.
#[derive(AlignedBorrow, Serialize, Deserialize, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct RecursionPublicValues<T> {
    /// The `committed_value_digest` before this shard.
    pub prev_committed_value_digest: [[T; 4]; PV_DIGEST_NUM_WORDS],

    /// The hash of all the bytes that the program has written to public values.
    pub committed_value_digest: [[T; 4]; PV_DIGEST_NUM_WORDS],

    /// The `deferred_proofs_digest` before this shard.
    pub prev_deferred_proofs_digest: [T; POSEIDON_NUM_WORDS],

    /// The hash of all deferred proofs that have been witnessed in the VM.
    pub deferred_proofs_digest: [T; POSEIDON_NUM_WORDS],

    /// The deferred proof index before this shard.
    pub prev_deferred_proof: T,

    /// The deferred proof index after this shard.
    pub deferred_proof: T,

    /// The chunk index before this chunk.
    pub prev_chunk_index: T,

    /// The chunk index after this chunk.
    pub last_chunk_index: T,

    /// The start pc of shards being proven.
    pub pc_start: [T; 3],

    /// The expected start pc for the next shard.
    pub next_pc: [T; 3],

    /// The initial timestamp.
    pub initial_timestamp: [T; 4],

    /// The last timestamp.
    pub last_timestamp: [T; 4],

    /// The initial memory root.
    pub initial_memory_root: [T; POSEIDON_NUM_WORDS],

    /// The last memory root.
    pub last_memory_root: [T; POSEIDON_NUM_WORDS],

    /// Start state of reconstruct_deferred_digest.
    pub start_reconstruct_deferred_digest: [T; POSEIDON_NUM_WORDS],

    /// End state of reconstruct_deferred_digest.
    pub end_reconstruct_deferred_digest: [T; POSEIDON_NUM_WORDS],

    /// The commitment to the sp1 program being proven.
    pub sp1_vk_digest: [T; DIGEST_SIZE],

    /// The root of the vk merkle tree.
    pub vk_root: [T; DIGEST_SIZE],

    /// Whether or not the first shard is inside the compress proof.
    pub contains_first_shard: T,

    /// The total number of included core shards inside the compress proof.
    pub num_included_shard: T,

    /// Whether the proof completely proves the program execution.
    pub is_complete: T,

    /// The expected exit code of the program before this shard.
    pub prev_exit_code: T,

    /// The expected exit code of the program up to this shard.
    pub exit_code: T,

    /// The `commit_syscall` value of the previous shard.
    pub prev_commit_syscall: T,

    /// Whether `COMMIT` syscall has been called up to this shard.
    pub commit_syscall: T,

    /// The `commit_deferred_syscall` value of the previous shard.
    pub prev_commit_deferred_syscall: T,

    /// Whether `COMMIT_DEFERRED` syscall has been called up to this shard.
    pub commit_deferred_syscall: T,

    /// The nonce used for this proof.
    pub proof_nonce: [T; PROOF_NONCE_NUM_WORDS],

    /// The shard index before this shard.
    pub prev_shard_index: T,

    /// The shard index after this shard.
    pub last_shard_index: T,

    /// The number of merkle shards in this chunk.
    pub num_merkle_shard: T,

    /// The number of execution shards in this chunk.
    pub num_execution_shard: T,

    /// Start state of reconstruct global challenge.
    pub start_reconstruct_global_challenge: [T; PERMUTATION_WIDTH],

    /// End state of reconstruct global challenge.
    pub end_reconstruct_global_challenge: [T; PERMUTATION_WIDTH],

    /// The global commitments hash.
    pub global_commitments_hash: [T; POSEIDON_NUM_WORDS],

    /// Whether the proof completely proves the chunk.
    pub is_chunk_complete: T,

    /// Current cumulative sum of lookup bus.
    pub global_cumulative_sum: [T; 4],

    /// The digest of all the previous public values elements.
    pub digest: [T; DIGEST_SIZE],
}

/// Converts the public values to an array of elements.
impl<F: Copy> RecursionPublicValues<F> {
    pub fn as_array(&self) -> [F; RECURSIVE_PROOF_NUM_PV_ELTS] {
        unsafe {
            let mut ret = [MaybeUninit::<F>::zeroed().assume_init(); RECURSIVE_PROOF_NUM_PV_ELTS];
            let pv: &mut RecursionPublicValues<F> = ret.as_mut_slice().borrow_mut();
            *pv = *self;
            ret
        }
    }

    pub fn range(&self) -> ShardRange
    where
        F: PrimeField32,
    {
        let initial_timestamp = timestamp_from_limbs(&self.initial_timestamp);
        let last_timestamp = timestamp_from_limbs(&self.last_timestamp);

        let prev_deferred_proof = self.prev_deferred_proof.as_canonical_u64();
        let deferred_proof = self.deferred_proof.as_canonical_u64();

        ShardRange {
            timestamp_range: (initial_timestamp, last_timestamp),
            deferred_proof_range: (prev_deferred_proof, deferred_proof),
        }
    }
}

impl<T: Copy> IntoIterator for RecursionPublicValues<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, RECURSIVE_PROOF_NUM_PV_ELTS>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_array().into_iter()
    }
}
