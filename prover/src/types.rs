use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use sp1_core::{
    air::{PublicValues, Word, POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS},
    stark::{ShardProof, StarkGenericConfig, Val},
};
use sp1_recursion_core::air::RecursionPublicValues;

use crate::{CoreSC, SP1ReduceProof};

/// Represents the state of reducing proofs together. This is used to track the current values since
/// some reduce batches may have only deferred proofs.
#[derive(Clone)]
pub struct ReduceState {
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
