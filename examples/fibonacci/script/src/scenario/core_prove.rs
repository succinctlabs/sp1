use crate::{
    common,
    operator::{
        operator_absorb_commits, operator_construct_sp1_core_proof, operator_split_into_checkpoints,
    },
    worker::{worker_commit_checkpoint, worker_prove_checkpoint},
    ProveArgs, PublicValuesTuple,
};
use alloy_sol_types::SolType;
use anyhow::Result;
use sp1_prover::SP1CoreProof;
use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues};

pub fn mpc_prove_core(args: ProveArgs) -> Result<Vec<u8>> {
    // Setup the prover client.
    let serialize_args = bincode::serialize(&args).unwrap();

    let mut public_values_stream = Vec::new();
    let mut public_values = Vec::new();
    let mut checkpoints = Vec::new();
    let mut cycles = 0;
    operator_split_into_checkpoints(
        &serialize_args,
        &mut public_values_stream,
        &mut public_values,
        &mut checkpoints,
        &mut cycles,
    );

    let mut commitments_vec = Vec::new();
    let mut records_vec = Vec::new();
    let num_checkpoints = checkpoints.len();
    for (idx, checkpoint) in checkpoints.iter_mut().enumerate() {
        let is_last_checkpoint = idx == num_checkpoints - 1;
        let mut commitments = Vec::new();
        let mut records = Vec::new();
        worker_commit_checkpoint(
            &serialize_args,
            idx as u32,
            checkpoint,
            is_last_checkpoint,
            &public_values,
            &mut commitments,
            &mut records,
        );
        commitments_vec.push(commitments);
        records_vec.push(records);
        tracing::info!("{:?}-th phase1 worker done", idx);
    }

    let mut challenger_state = Vec::new();
    operator_absorb_commits(
        &serialize_args,
        &commitments_vec,
        &records_vec,
        &mut challenger_state,
    );

    let mut shard_proofs_vec = Vec::new();
    for (idx, records) in records_vec.into_iter().enumerate() {
        let mut shard_proofs = Vec::new();
        worker_prove_checkpoint(
            &serialize_args,
            &challenger_state,
            records.as_slice(),
            &mut shard_proofs,
        );
        shard_proofs_vec.push(shard_proofs);
        tracing::info!("{:?}-th phase2 worker done", idx);
    }

    // Core proof.
    let mut proof = Vec::new();
    operator_construct_sp1_core_proof(
        &serialize_args,
        &shard_proofs_vec,
        &public_values_stream,
        cycles,
        &mut proof,
    );

    Ok(proof)
}

pub fn scenario_end(args: ProveArgs, core_proof: &Vec<u8>) -> Result<SP1ProofWithPublicValues> {
    let core_proof_obj: SP1CoreProof = bincode::deserialize(core_proof).unwrap();

    let (client, _, _, vk) = common::init_client(args);

    let proof = SP1ProofWithPublicValues {
        proof: SP1Proof::Core(core_proof_obj.proof.0),
        stdin: core_proof_obj.stdin,
        public_values: core_proof_obj.public_values,
        sp1_version: client.prover.version().to_string(),
    };

    client.verify(&proof, &vk).expect("failed to verify proof");
    tracing::info!("Successfully generated core-proof(verified)");

    let (_, _, fib_n) =
        PublicValuesTuple::abi_decode(proof.public_values.as_slice(), false).unwrap();
    tracing::info!("Public Input: {}", fib_n);

    Ok(proof)
}
