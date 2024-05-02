use p3_baby_bear::BabyBear;
use p3_field::{AbstractField, PrimeField32, TwoAdicField};
use serde::{Deserialize, Serialize};
use sp1_core::{
    air::{PublicValues, Word, POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS},
    io::{SP1PublicValues, SP1Stdin},
    stark::{ShardProof, StarkGenericConfig, StarkProvingKey, StarkVerifyingKey, Val},
    utils::DIGEST_SIZE,
};
use sp1_primitives::poseidon2_hash;
use sp1_recursion_core::air::RecursionPublicValues;

use crate::{CoreSC, InnerSC};

/// The information necessary to generate a proof for a given RISC-V program.
pub struct SP1ProvingKey {
    pub pk: StarkProvingKey<CoreSC>,
    pub elf: Vec<u8>,
    /// Verifying key is also included as we need it for recursion
    pub vk: SP1VerifyingKey,
}

/// The information necessary to verify a proof for a given RISC-V program.
#[derive(Clone)]
pub struct SP1VerifyingKey {
    pub vk: StarkVerifyingKey<CoreSC>,
}

impl SP1VerifyingKey {
    pub fn hash(&self) -> [BabyBear; 8] {
        let prep_domains = self.vk.chip_information.iter().map(|(_, domain, _)| domain);
        let num_inputs = DIGEST_SIZE + 1 + (4 * prep_domains.len());
        let mut inputs = Vec::with_capacity(num_inputs);
        inputs.extend(self.vk.commit.as_ref());
        inputs.push(self.vk.pc_start);
        for domain in prep_domains {
            inputs.push(BabyBear::from_canonical_usize(domain.log_n));
            let size = 1 << domain.log_n;
            inputs.push(BabyBear::from_canonical_usize(size));
            let g = BabyBear::two_adic_generator(domain.log_n);
            inputs.push(domain.shift);
            inputs.push(g);
        }

        poseidon2_hash(inputs)
    }

    pub fn hash_u32(&self) -> [u32; 8] {
        self.hash()
            .into_iter()
            .map(|n| n.as_canonical_u32())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
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

/// A proof that can be reduced along with other proofs into one proof.
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
