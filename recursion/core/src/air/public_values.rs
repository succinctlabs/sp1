use crate::runtime::{DIGEST_SIZE, PERMUTATION_WIDTH};

use core::fmt::Debug;
use p3_challenger::DuplexChallenger;
use p3_field::PrimeField32;
use p3_symmetric::CryptographicPermutation;
use serde::{Deserialize, Serialize};
use sp1_core::{
    air::{Word, POSEIDON_NUM_WORDS},
    stark::PROOF_MAX_NUM_PVS,
};
use sp1_derive::AlignedBorrow;
use static_assertions::const_assert_eq;
use std::mem::size_of;

pub const PV_DIGEST_NUM_WORDS: usize = 8;

pub const CHALLENGER_STATE_NUM_ELTS: usize = 50;

pub const RECURSIVE_PROOF_NUM_PV_ELTS: usize = size_of::<RecursionPublicValues<u8>>();

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
    // pub fn from_vec(data: Vec<T>) -> Self {
    //     if data.len() < CHALLENGER_STATE_NUM_ELTS {
    //         panic!("Invalid number of items in the serialized vector.");
    //     }

    //     let mut iter = data.iter().cloned();
    //     let sponge_state = iter.by_ref().take(PERMUTATION_WIDTH).collect::<Vec<_>>();
    //     let num_inputs = iter.next().unwrap();
    //     let input_buffer = iter.by_ref().take(PERMUTATION_WIDTH).collect::<Vec<_>>();
    //     let num_outputs = iter.next().unwrap();
    //     let output_buffer = iter.by_ref().take(PERMUTATION_WIDTH).collect::<Vec<_>>();

    //     Self {
    //         sponge_state: unwrap_into_array(sponge_state),
    //         num_inputs,
    //         input_buffer: unwrap_into_array(input_buffer),
    //         num_outputs,
    //         output_buffer: unwrap_into_array(output_buffer),
    //     }
    // }

    pub fn set_challenger<P: CryptographicPermutation<[T; PERMUTATION_WIDTH]>>(
        &self,
        challenger: &mut DuplexChallenger<T, P, PERMUTATION_WIDTH>,
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

    /// The exit code of the program.
    pub exit_code: T,

    /// First shard being proven.
    pub start_shard: T,

    /// Next shard that should be proven, or 0 if the program halted.
    pub next_shard: T,

    /// Start state of reconstruct_challenger.
    pub start_reconstruct_challenger: ChallengerPublicValues<T>,

    /// End state of reconstruct_challenger.
    pub end_reconstruct_challenger: ChallengerPublicValues<T>,

    /// Start state of reconstruct_deferred_digest.
    pub start_reconstruct_deferred_digest: [T; POSEIDON_NUM_WORDS],

    /// End state of reconstruct_deferred_digest.
    pub end_reconstruct_deferred_digest: [T; POSEIDON_NUM_WORDS],

    /// The commitment to the sp1 program being proven.
    pub vk_digest: [T; DIGEST_SIZE],

    /// The commitment to the start program being proven.
    pub verify_start_challenger: ChallengerPublicValues<T>,

    /// Current cumulative sum of lookup bus.
    pub cumulative_sum: [T; 4],

    /// Whether the proof completely proves the program execution.
    pub is_complete: T,
}

// impl<T: Clone + Debug> RecursionPublicValues<T> {
//     /// Convert a vector of field elements into a PublicValues struct.
//     pub fn from_vec(data: Vec<T>) -> Self {
//         if data.len() != RECURSIVE_PROOF_NUM_PV_ELTS {
//             panic!("Invalid number of items in the serialized vector.");
//         }

//         let mut iter = data.iter().cloned();
//         let committed_value_digest = (0..PV_DIGEST_NUM_WORDS)
//             .map(|_| Word::from_iter(iter.by_ref()))
//             .collect();
//         let deferred_proofs_digest = iter.by_ref().take(POSEIDON_NUM_WORDS).collect::<Vec<_>>();
//         let start_pc = iter.next().unwrap();
//         let next_pc = iter.next().unwrap();
//         let exit_code = iter.next().unwrap();
//         let start_shard = iter.next().unwrap();
//         let next_shard = iter.next().unwrap();
//         let start_reconstruct_challenger = ChallengerPublicValues::from_vec(
//             iter.by_ref()
//                 .take(CHALLENGER_STATE_NUM_ELTS)
//                 .collect::<Vec<_>>(),
//         );
//         let end_reconstruct_challenger = ChallengerPublicValues::from_vec(
//             iter.by_ref()
//                 .take(CHALLENGER_STATE_NUM_ELTS)
//                 .collect::<Vec<_>>(),
//         );
//         let start_reconstruct_deferred_digest = iter.by_ref().take(DIGEST_SIZE).collect::<Vec<_>>();
//         let end_reconstruct_deferred_digest = iter.by_ref().take(DIGEST_SIZE).collect::<Vec<_>>();
//         let sp1_vk_commit = iter.by_ref().take(DIGEST_SIZE).collect::<Vec<_>>();
//         let recursion_vk_commit = iter.by_ref().take(DIGEST_SIZE).collect::<Vec<_>>();
//         let verify_start_challenger = ChallengerPublicValues::from_vec(
//             iter.by_ref()
//                 .take(CHALLENGER_STATE_NUM_ELTS)
//                 .collect::<Vec<_>>(),
//         );
//         let cumulative_sum = iter.by_ref().take(4).collect::<Vec<_>>();
//         let is_complete = iter.next().unwrap();

//         Self {
//             committed_value_digest: unwrap_into_array(committed_value_digest),
//             deferred_proofs_digest: unwrap_into_array(deferred_proofs_digest),
//             start_pc,
//             next_pc,
//             exit_code,
//             start_shard,
//             next_shard,
//             start_reconstruct_challenger,
//             end_reconstruct_challenger,
//             start_reconstruct_deferred_digest: unwrap_into_array(start_reconstruct_deferred_digest),
//             end_reconstruct_deferred_digest: unwrap_into_array(end_reconstruct_deferred_digest),
//             sp1_vk_digest: unwrap_into_array(sp1_vk_commit),
//             recursion_vk_digest: unwrap_into_array(recursion_vk_commit),
//             verify_start_challenger,
//             cumulative_sum: unwrap_into_array(cumulative_sum),
//             is_complete,
//         }
//     }
// }

// /// Convert a vector into an array, panicking if the length is incorrect.
// fn unwrap_into_array<T: Debug, const N: usize>(input: Vec<T>) -> [T; N] {
//     input.try_into().unwrap()
// }
