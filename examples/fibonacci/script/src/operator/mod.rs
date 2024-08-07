pub mod steps;
pub mod utils;

use crate::ProveArgs;
use steps::prove_begin_impl;
use utils::read_bin_file_to_vec;

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
