use super::types::{DeferredLayout, RecursionLayout, ReduceLayout};
use crate::multi_prover::operator::utils::ChallengerState;
use p3_baby_bear::BabyBear;
use serde::{Deserialize, Serialize};
use sp1_core::{air::Word, stark::ShardProof, utils::BabyBearPoseidon2};
use sp1_prover::ReduceProgramType;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableRecursionLayout {
    pub shard_proofs: Vec<ShardProof<BabyBearPoseidon2>>,
    pub leaf_challenger: ChallengerState,
    pub initial_reconstruct_challenger: ChallengerState,
    pub is_complete: bool,
}

impl SerializableRecursionLayout {
    pub fn from_layout(mut layout: RecursionLayout) -> Self {
        Self {
            shard_proofs: layout.shard_proofs.drain(..).collect(),
            leaf_challenger: ChallengerState::from(layout.leaf_challenger),
            initial_reconstruct_challenger: ChallengerState::from(
                &layout.initial_reconstruct_challenger,
            ),
            is_complete: layout.is_complete,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableDeferredLayout {
    pub proofs: Vec<ShardProof<BabyBearPoseidon2>>,
    pub start_reconstruct_deferred_digest: Vec<BabyBear>,

    pub is_complete: bool,

    pub committed_value_digest: Vec<Word<BabyBear>>,
    pub deferred_proofs_digest: Vec<BabyBear>,
    pub leaf_challenger: ChallengerState,
    pub end_pc: BabyBear,
    pub end_shard: BabyBear,
    pub end_execution_shard: BabyBear,
    pub init_addr_bits: [BabyBear; 32],
    pub finalize_addr_bits: [BabyBear; 32],
}

impl SerializableDeferredLayout {
    pub fn from_layout(mut layout: DeferredLayout) -> Self {
        Self {
            proofs: layout.proofs.drain(..).collect(),
            start_reconstruct_deferred_digest: layout
                .start_reconstruct_deferred_digest
                .drain(..)
                .collect(),
            is_complete: layout.is_complete,
            committed_value_digest: layout.committed_value_digest.drain(..).collect(),
            deferred_proofs_digest: layout.deferred_proofs_digest.drain(..).collect(),
            leaf_challenger: ChallengerState::from(&layout.leaf_challenger),
            end_pc: layout.end_pc,
            end_shard: layout.end_shard,
            end_execution_shard: layout.end_execution_shard,
            init_addr_bits: layout.init_addr_bits,
            finalize_addr_bits: layout.finalize_addr_bits,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableReduceLayout {
    pub shard_proofs: Vec<ShardProof<BabyBearPoseidon2>>,
    pub is_complete: bool,
    pub kinds: Vec<ReduceProgramType>,
}

impl SerializableReduceLayout {
    pub fn from_layout(mut layout: ReduceLayout) -> Self {
        Self {
            shard_proofs: layout.shard_proofs.drain(..).collect(),
            is_complete: layout.is_complete,
            kinds: layout.kinds.drain(..).collect(),
        }
    }
}
