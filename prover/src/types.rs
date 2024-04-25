use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use serde::{Deserialize, Serialize};
use sp1_core::{
    air::{PublicValues, Word, POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS},
    io::{SP1PublicValues, SP1Stdin},
    runtime::Program,
    stark::{ShardProof, StarkGenericConfig, StarkProvingKey, StarkVerifyingKey, Val},
};
use sp1_recursion_core::air::RecursionPublicValues;

use crate::{CoreSC, InnerSC};

/// The information necessary to generate a proof for a given RISC-V program.
pub struct SP1ProvingKey {
    pub pk: StarkProvingKey<CoreSC>,
    pub program: Program,
}

/// The information necessary to verify a proof for a given RISC-V program.
pub struct SP1VerifyingKey {
    pub vk: StarkVerifyingKey<CoreSC>,
}

/// A proof of a RISC-V execution with given inputs and outputs composed of multiple shard proofs.
#[derive(Serialize, Deserialize, Clone)]
pub struct SP1CoreProof {
    pub shard_proofs: Vec<ShardProof<CoreSC>>,
    pub stdin: SP1Stdin,
    pub public_values: SP1PublicValues,
}

/// An intermediate proof which proves the execution over a range of shards.
#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "ShardProof<SC>: Serialize"))]
#[serde(bound(deserialize = "ShardProof<SC>: Deserialize<'de>"))]
pub struct SP1ReduceProof<SC: StarkGenericConfig> {
    pub proof: ShardProof<SC>,
}

/// A wrapper to abstract proofs representing a range of shards with multiple proving configs.
#[derive(Serialize, Deserialize)]
pub enum SP1ReduceProofWrapper {
    Core(SP1ReduceProof<CoreSC>),
    Recursive(SP1ReduceProof<InnerSC>),
}

/// Represents the state of reducing proofs together. This is used to track the current values since
/// some reduce batches may have only deferred proofs.
#[derive(Clone)]
pub(crate) struct ReduceState {
    pub committed_values_digest: [Word<Val<CoreSC>>; PV_DIGEST_NUM_WORDS],
    pub deferred_proofs_digest: [Val<CoreSC>; POSEIDON_NUM_WORDS],
    pub start_pc: Val<CoreSC>,
    pub exit_code: Val<CoreSC>,
    pub start_shard: Val<CoreSC>,
    pub reconstruct_deferred_digest: [Val<CoreSC>; POSEIDON_NUM_WORDS],
}

impl ReduceState {
    pub fn from_reduce_end_state<SC: StarkGenericConfig<Val = BabyBear>>(
        state: &SP1ReduceProof<SC>,
    ) -> Self {
        let pv = RecursionPublicValues::from_vec(state.proof.public_values.clone());
        Self {
            committed_values_digest: pv.committed_value_digest,
            deferred_proofs_digest: pv.deferred_proofs_digest,
            start_pc: pv.next_pc,
            exit_code: pv.exit_code,
            start_shard: pv.next_shard,
            reconstruct_deferred_digest: pv.end_reconstruct_deferred_digest,
        }
    }

    pub fn from_reduce_start_state<SC: StarkGenericConfig<Val = BabyBear>>(
        state: &SP1ReduceProof<SC>,
    ) -> Self {
        let pv = RecursionPublicValues::from_vec(state.proof.public_values.clone());
        Self {
            committed_values_digest: pv.committed_value_digest,
            deferred_proofs_digest: pv.deferred_proofs_digest,
            start_pc: pv.start_pc,
            exit_code: pv.exit_code,
            start_shard: pv.start_shard,
            reconstruct_deferred_digest: pv.start_reconstruct_deferred_digest,
        }
    }

    pub fn from_core_start_state(state: &ShardProof<CoreSC>) -> Self {
        let pv =
            PublicValues::<Word<Val<CoreSC>>, Val<CoreSC>>::from_vec(state.public_values.clone());
        Self {
            committed_values_digest: pv.committed_value_digest,
            deferred_proofs_digest: pv.deferred_proofs_digest,
            start_pc: pv.start_pc,
            exit_code: pv.exit_code,
            start_shard: pv.shard,
            // TODO: we assume that core proofs aren't in a later batch than one with a deferred proof
            reconstruct_deferred_digest: [BabyBear::zero(); 8],
        }
    }
}
