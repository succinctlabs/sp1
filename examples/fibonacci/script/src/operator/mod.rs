pub mod steps;
pub mod utils;

use crate::{
    common::types::{CommitmentType, RecordType},
    ProveArgs,
};
use sp1_core::{stark::ShardProof, utils::BabyBearPoseidon2};
use steps::{operator_phase1_impl, operator_phase2_impl, prove_begin_impl};
use utils::{read_bin_file_to_vec, ChallengerState};

pub fn prove_begin(
    args: &[u8],
    o_public_values_stream: &mut Vec<u8>,
    o_public_values: &mut Vec<u8>,
    o_checkpoints: &mut Vec<Vec<u8>>,
    o_cycles: &mut u64,
) {
    let args_obj = ProveArgs::from_slice(args);
    let (public_values_stream, public_values, checkpoints, cycles) =
        prove_begin_impl(args_obj).unwrap();

    *o_public_values_stream = bincode::serialize(&public_values_stream).unwrap();
    *o_public_values = bincode::serialize(&public_values).unwrap();
    *o_checkpoints = checkpoints
        .into_iter()
        .map(|checkpoint| read_bin_file_to_vec(checkpoint).unwrap())
        .collect();
    *o_cycles = cycles;
}

pub fn operator_phase1(
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

    let challenger = operator_phase1_impl(args_obj, commitments_vec, records_vec).unwrap();
    *o_challenger_state = ChallengerState::from(&challenger).to_bytes();
}

pub fn operator_phase2(
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
    let proof = operator_phase2_impl(
        args_obj,
        shard_proofs_vec_obj,
        public_values_stream.to_vec(),
        cycles,
    )
    .unwrap();
    *o_proof = bincode::serialize(&proof).unwrap();
}
