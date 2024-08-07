pub mod steps;
pub mod utils;

use crate::{
    common::types::{CommitmentType, RecordType},
    ProveArgs,
};
use steps::{operator_phase1_impl, prove_begin_impl};
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
