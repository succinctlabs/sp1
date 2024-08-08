pub mod steps;

use crate::{
    common::{self, types::RecordType},
    operator::utils::ChallengerState,
    ProveArgs,
};
use sp1_core::{runtime::ExecutionState, stark::MachineProver};
use steps::{worker_phase1_impl, worker_phase2_impl};

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

pub fn worker_phase2(
    args: &Vec<u8>,
    challenger_state: &Vec<u8>,
    records: &[u8],
    o_shard_proofs: &mut Vec<u8>,
) {
    let args_obj = ProveArgs::from_slice(args.as_slice());
    let (client, _, _, _) = common::init_client(args_obj.clone());
    let challenger = ChallengerState::from_bytes(challenger_state.as_slice())
        .to_challenger(&client.prover.sp1_prover().core_prover.config().perm);
    let records: Vec<RecordType> = bincode::deserialize(records).unwrap();

    let shard_proofs = worker_phase2_impl(args_obj, challenger, records).unwrap();
    let result = bincode::serialize(&shard_proofs.as_slice()).unwrap();
    *o_shard_proofs = result;
}
