pub mod steps;

use crate::multi_prover::common;
use crate::multi_prover::common::memory_layouts::SerializableReduceLayout;
use crate::multi_prover::{
    common::{
        memory_layouts::{SerializableDeferredLayout, SerializableRecursionLayout},
        types::LayoutType,
        ProveArgs,
    },
    operator::utils::ChallengerState,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sp1_core::{runtime::ExecutionState, stark::MachineProver};
use steps::{
    worker_commit_checkpoint_impl, worker_compress_proofs_for_deferred,
    worker_compress_proofs_for_recursion, worker_compress_proofs_for_reduce,
    worker_prove_checkpoint_impl,
};

pub fn worker_commit_checkpoint<T: Serialize + DeserializeOwned>(
    args: &Vec<u8>,
    idx: u32,
    checkpoint: &Vec<u8>,
    is_last_checkpoint: bool,
    public_values: &[u8],
    o_commitments: &mut Vec<Vec<u8>>,
    o_records: &mut Vec<Vec<u8>>,
) {
    let args_obj: ProveArgs<T> = ProveArgs::from_slice(args.as_slice());
    let execution_state: ExecutionState = bincode::deserialize(checkpoint.as_slice()).unwrap();
    let mut checkpoint_file = tempfile::tempfile().unwrap();
    execution_state.save(&mut checkpoint_file).unwrap();
    let public_values_obj = bincode::deserialize(public_values).unwrap();

    let (commitments, records) = worker_commit_checkpoint_impl(
        &args_obj,
        idx,
        &mut checkpoint_file,
        is_last_checkpoint,
        public_values_obj,
    )
    .unwrap();
    tracing::info!("{:?} commitments were generated", commitments.len());

    *o_commitments = commitments
        .iter()
        .map(|commitment| bincode::serialize(commitment).unwrap())
        .collect();
    *o_records = records
        .iter()
        .map(|record| bincode::serialize(record).unwrap())
        .collect();
}

pub fn worker_prove_checkpoint<T: Serialize + DeserializeOwned>(
    args: &Vec<u8>,
    challenger_state: &Vec<u8>,
    records: &[Vec<u8>],
    o_shard_proofs: &mut Vec<Vec<u8>>,
) {
    let args_obj: ProveArgs<T> = ProveArgs::from_slice(args.as_slice());
    let (client, _, _, _) = common::init_client(&args_obj);
    let challenger = ChallengerState::from_bytes(challenger_state.as_slice())
        .to_challenger(&client.prover.sp1_prover().core_prover.config().perm);
    let records = records
        .iter()
        .map(|record| bincode::deserialize(record).unwrap())
        .collect();

    let shard_proofs = worker_prove_checkpoint_impl(&args_obj, challenger, records).unwrap();
    tracing::info!("{:?} shard proofs were generated", shard_proofs.len());

    *o_shard_proofs = shard_proofs
        .iter()
        .map(|proof| bincode::serialize(proof).unwrap())
        .collect();
}

pub fn worker_compress_proofs<T: Serialize + DeserializeOwned>(
    args: &Vec<u8>,
    layout: &Vec<u8>,
    layout_type: usize,
    last_proof_public_values: Option<&Vec<u8>>,
    o_proof: &mut Vec<u8>,
) {
    let args_obj: ProveArgs<T> = ProveArgs::from_slice(args.as_slice());
    let compressed_shard_proof = match LayoutType::from_usize(layout_type) {
        LayoutType::Recursion => {
            let layout: SerializableRecursionLayout = bincode::deserialize(layout).unwrap();
            tracing::info!("recursion program proof generation was requested");
            worker_compress_proofs_for_recursion(&args_obj, layout).unwrap()
        }
        LayoutType::Deferred => {
            let layout: SerializableDeferredLayout = bincode::deserialize(layout).unwrap();
            let last_public_values =
                bincode::deserialize(last_proof_public_values.unwrap()).unwrap();
            tracing::info!("deferred program proof generation was requested");
            worker_compress_proofs_for_deferred(&args_obj, layout, last_public_values).unwrap()
        }
        LayoutType::Reduce => {
            let layout: SerializableReduceLayout = bincode::deserialize(layout).unwrap();
            tracing::info!("reduce program proof generation was requested");
            worker_compress_proofs_for_reduce(&args_obj, layout).unwrap()
        }
    };

    *o_proof = bincode::serialize(&compressed_shard_proof).unwrap();
}
