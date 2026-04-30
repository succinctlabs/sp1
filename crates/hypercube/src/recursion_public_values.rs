use crate::DIGEST_SIZE;
use core::fmt::Debug;
use serde::{Deserialize, Serialize};
use slop_algebra::PrimeField32;
use sp1_derive::AlignedBorrow;

use crate::{
    air::{timestamp_from_limbs, ShardRange, POSEIDON_NUM_WORDS, PROOF_NONCE_NUM_WORDS},
    indices_arr,
    septic_digest::SepticDigest,
    PROOF_MAX_NUM_PVS,
};
use static_assertions::const_assert_eq;
use std::{
    borrow::BorrowMut,
    mem::{size_of, transmute, MaybeUninit},
};

/// The number of words in the public values digest.
pub const PV_DIGEST_NUM_WORDS: usize = 8;

/// The total number of elements in the recursion public values struct.
pub const RECURSIVE_PROOF_NUM_PV_ELTS: usize = size_of::<RecursionPublicValues<u8>>();

const fn make_col_map() -> RecursionPublicValues<usize> {
    let indices_arr = indices_arr::<RECURSIVE_PROOF_NUM_PV_ELTS>();
    unsafe {
        transmute::<[usize; RECURSIVE_PROOF_NUM_PV_ELTS], RecursionPublicValues<usize>>(indices_arr)
    }
}

/// A column map that provides the index of each field in the public values struct.
pub const RECURSION_PUBLIC_VALUES_COL_MAP: RecursionPublicValues<usize> = make_col_map();

/// The number of public value elements that are hashed to produce the digest.
/// All fields before `digest` are included.
pub const NUM_PV_ELMS_TO_HASH: usize = RECURSION_PUBLIC_VALUES_COL_MAP.digest[0];

// Recursive proof has more public values than core proof, so the max number constant defined in
// sp1_core should be set to `RECURSIVE_PROOF_NUM_PV_ELTS`.
const_assert_eq!(RECURSIVE_PROOF_NUM_PV_ELTS, PROOF_MAX_NUM_PVS);

/// The `PublicValues` struct is used to store all of a recursion proof's public values.
#[allow(clippy::unsafe_derive_deserialize)]
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

    /// The start pc of shards being proven.
    pub pc_start: [T; 3],

    /// The expected start pc for the next shard.
    pub next_pc: [T; 3],

    /// The initial timestamp.
    pub initial_timestamp: [T; 4],

    /// The last timestamp.
    pub last_timestamp: [T; 4],

    /// Previous `MemoryInit` address.
    pub previous_init_addr: [T; 3],

    /// Last `MemoryInit` address.
    pub last_init_addr: [T; 3],

    /// Previous `MemoryFinalize` address.
    pub previous_finalize_addr: [T; 3],

    /// Last `MemoryFinalize` address.
    pub last_finalize_addr: [T; 3],

    /// Previous `PageProtInit` page index.
    pub previous_init_page_idx: [T; 3],

    /// Last `PageProtInit` page index.
    pub last_init_page_idx: [T; 3],

    /// Previous `PageProtFinalize` page index.
    pub previous_finalize_page_idx: [T; 3],

    /// Last `PageProtFinalize` page index.
    pub last_finalize_page_idx: [T; 3],

    /// Start state of `reconstruct_deferred_digest`.
    pub start_reconstruct_deferred_digest: [T; POSEIDON_NUM_WORDS],

    /// End state of `reconstruct_deferred_digest`.
    pub end_reconstruct_deferred_digest: [T; POSEIDON_NUM_WORDS],

    /// The commitment to the sp1 program being proven.
    pub sp1_vk_digest: [T; DIGEST_SIZE],

    /// The root of the vk merkle tree.
    pub vk_root: [T; DIGEST_SIZE],

    /// Current cumulative sum of lookup bus. Note that for recursive proofs for core proofs, this
    /// contains the global cumulative sum.
    pub global_cumulative_sum: SepticDigest<T>,

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

    /// The digest of all the previous public values elements.
    pub digest: [T; DIGEST_SIZE],

    /// The nonce used for this proof.
    pub proof_nonce: [T; PROOF_NONCE_NUM_WORDS],
}

/// Converts the public values to an array of elements.
impl<F: Copy> RecursionPublicValues<F> {
    /// Converts the public values to a flat array of elements.
    pub fn as_array(&self) -> [F; RECURSIVE_PROOF_NUM_PV_ELTS] {
        unsafe {
            let mut ret = [MaybeUninit::<F>::zeroed().assume_init(); RECURSIVE_PROOF_NUM_PV_ELTS];
            let pv: &mut RecursionPublicValues<F> = ret.as_mut_slice().borrow_mut();
            *pv = *self;
            ret
        }
    }

    /// Extracts the shard range information from the public values.
    pub fn range(&self) -> ShardRange
    where
        F: PrimeField32,
    {
        let initial_timestamp = timestamp_from_limbs(&self.initial_timestamp);
        let last_timestamp = timestamp_from_limbs(&self.last_timestamp);
        let previous_init_addr = self
            .previous_init_addr
            .iter()
            .rev()
            .fold(0, |acc, x| acc * (1 << 16) + x.as_canonical_u32() as u64);
        let last_init_addr = self
            .last_init_addr
            .iter()
            .rev()
            .fold(0, |acc, x| acc * (1 << 16) + x.as_canonical_u32() as u64);
        let previous_finalize_addr = self
            .previous_finalize_addr
            .iter()
            .rev()
            .fold(0, |acc, x| acc * (1 << 16) + x.as_canonical_u32() as u64);
        let last_finalize_addr = self
            .last_finalize_addr
            .iter()
            .rev()
            .fold(0, |acc, x| acc * (1 << 16) + x.as_canonical_u32() as u64);
        let previous_init_page_idx = self
            .previous_init_page_idx
            .iter()
            .rev()
            .fold(0, |acc, x| acc * (1 << 16) + x.as_canonical_u32() as u64);
        let last_init_page_idx = self
            .last_init_page_idx
            .iter()
            .rev()
            .fold(0, |acc, x| acc * (1 << 16) + x.as_canonical_u32() as u64);
        let previous_finalize_page_idx = self
            .previous_finalize_page_idx
            .iter()
            .rev()
            .fold(0, |acc, x| acc * (1 << 16) + x.as_canonical_u32() as u64);
        let last_finalize_page_idx = self
            .last_finalize_page_idx
            .iter()
            .rev()
            .fold(0, |acc, x| acc * (1 << 16) + x.as_canonical_u32() as u64);

        let prev_deferred_proof = self.prev_deferred_proof.as_canonical_u64();
        let deferred_proof = self.deferred_proof.as_canonical_u64();

        ShardRange {
            timestamp_range: (initial_timestamp, last_timestamp),
            initialized_address_range: (previous_init_addr, last_init_addr),
            finalized_address_range: (previous_finalize_addr, last_finalize_addr),
            initialized_page_index_range: (previous_init_page_idx, last_init_page_idx),
            finalized_page_index_range: (previous_finalize_page_idx, last_finalize_page_idx),
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
