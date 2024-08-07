pub mod steps;

use crate::ProveArgs;
use sp1_core::runtime::ExecutionState;
use steps::worker_phase1_impl;

pub fn worker_phase1(
    args: &Vec<u8>,
    idx: u32,
    checkpoint: &Vec<u8>,
    is_last_checkpoint: bool,
    public_values: &[u8],
    o_commitments: &mut Vec<u8>,
    o_records: &mut Vec<u8>,
) {
    let args_obj = ProveArgs::from_slice(args.as_slice());
    let execution_state: ExecutionState = bincode::deserialize(checkpoint.as_slice()).unwrap();
    let mut checkpoint_file = tempfile::tempfile().unwrap();
    execution_state.save(&mut checkpoint_file).unwrap();
    let public_values_obj = bincode::deserialize(public_values).unwrap();

    let (commitments, records) = worker_phase1_impl(
        args_obj,
        idx,
        &mut checkpoint_file,
        is_last_checkpoint,
        public_values_obj,
    )
    .unwrap();

    *o_commitments = bincode::serialize(&commitments).unwrap();
    *o_records = bincode::serialize(&records).unwrap();
}
