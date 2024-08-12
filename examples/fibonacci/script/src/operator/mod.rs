pub mod steps;
pub mod utils;

use crate::common;
use crate::common::{
    memory_layouts::{SerializableDeferredLayout, SerializableRecursionLayout},
    types::{CommitmentType, RecordType},
};
use crate::ProveArgs;
use p3_baby_bear::BabyBear;
use sp1_core::air::{PublicValues, Word};
use sp1_core::stark::{MachineProver, StarkGenericConfig};
use sp1_core::{stark::ShardProof, utils::BabyBearPoseidon2};
use sp1_prover::SP1CoreProof;
use std::borrow::Borrow;
use steps::{
    construct_sp1_core_proof_impl, operator_absorb_commits_impl,
    operator_prepare_compress_inputs_impl, operator_split_into_checkpoints_impl,
};
use utils::{read_bin_file_to_vec, ChallengerState};

pub fn operator_split_into_checkpoints(
    args: &[u8],
    o_public_values_stream: &mut Vec<u8>,
    o_public_values: &mut Vec<u8>,
    o_checkpoints: &mut Vec<Vec<u8>>,
    o_cycles: &mut u64,
) {
    let args_obj = ProveArgs::from_slice(args);
    let (public_values_stream, public_values, checkpoints, cycles) =
        operator_split_into_checkpoints_impl(args_obj).unwrap();

    *o_public_values_stream = bincode::serialize(&public_values_stream).unwrap();
    *o_public_values = bincode::serialize(&public_values).unwrap();
    *o_checkpoints = checkpoints
        .into_iter()
        .map(|checkpoint| read_bin_file_to_vec(checkpoint).unwrap())
        .collect();
    *o_cycles = cycles;
}

pub fn operator_absorb_commits(
    args: &Vec<u8>,
    commitments_vec: &[Vec<u8>],
    records_vec: &[Vec<u8>],
    o_challenger_state: &mut Vec<u8>,
) {
    let args_obj = ProveArgs::from_slice(args.as_slice());
    let commitments_vec: Vec<Vec<CommitmentType>> = commitments_vec
        .iter()
        .map(|commitments| bincode::deserialize(commitments).unwrap())
        .collect();
    let records_vec: Vec<Vec<RecordType>> = records_vec
        .iter()
        .map(|records| bincode::deserialize(records).unwrap())
        .collect();

    let challenger = operator_absorb_commits_impl(args_obj, commitments_vec, records_vec).unwrap();
    *o_challenger_state = ChallengerState::from(&challenger).to_bytes();
}

pub fn operator_construct_sp1_core_proof(
    args: &Vec<u8>,
    shard_proofs_vec: &[Vec<u8>],
    public_values_stream: &[u8],
    cycles: u64,
    o_proof: &mut Vec<u8>,
) {
    let args_obj = ProveArgs::from_slice(args.as_slice());
    let shard_proofs_vec_obj: Vec<Vec<ShardProof<BabyBearPoseidon2>>> = shard_proofs_vec
        .iter()
        .map(|shard_proofs| bincode::deserialize(shard_proofs).unwrap())
        .collect();
    let proof = construct_sp1_core_proof_impl(
        args_obj,
        shard_proofs_vec_obj,
        public_values_stream.to_vec(),
        cycles,
    )
    .unwrap();
    *o_proof = bincode::serialize(&proof).unwrap();
}

pub fn operator_prepare_compress_inputs(
    args: &Vec<u8>,
    core_proof: &[u8],
    o_rec_layouts: &mut Vec<Vec<u8>>,
    o_def_layouts: &mut Vec<Vec<u8>>,
    o_last_proof_public_values: &mut Vec<u8>,
) {
    let args_obj = ProveArgs::from_slice(args.as_slice());
    let core_proof_obj: SP1CoreProof = bincode::deserialize(&core_proof).unwrap();

    let (client, stdin, _, vk) = common::init_client(args_obj);

    let mut leaf_challenger = client.prover.sp1_prover().core_prover.config().challenger();
    let (core_inputs, deferred_inputs) = operator_prepare_compress_inputs_impl(
        &stdin,
        &vk,
        &mut leaf_challenger,
        client.prover.sp1_prover(),
        &core_proof_obj,
    )
    .unwrap();

    *o_rec_layouts = core_inputs
        .into_iter()
        .map(|input| bincode::serialize(&SerializableRecursionLayout::from_layout(input)).unwrap())
        .collect();
    *o_def_layouts = deferred_inputs
        .into_iter()
        .map(|input| bincode::serialize(&SerializableDeferredLayout::from_layout(input)).unwrap())
        .collect();

    let last_public_values: &PublicValues<Word<BabyBear>, BabyBear> = &core_proof_obj
        .proof
        .0
        .last()
        .unwrap()
        .public_values
        .as_slice()
        .borrow();

    *o_last_proof_public_values = bincode::serialize(last_public_values).unwrap();
}
