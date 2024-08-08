use crate::common;
use crate::worker::CommitmentPairType;
use crate::ProveArgs;
use anyhow::Result;
use core::panic;
use p3_baby_bear::BabyBear;
use sp1_core::{
    air::PublicValues,
    runtime::Runtime,
    stark::{MachineProof, MachineProver, MachineRecord, StarkGenericConfig},
    utils::SP1CoreProverError,
};
use sp1_prover::{SP1CoreProof, SP1CoreProofData};
use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues, SP1PublicValues};
use std::fs::File;

pub type PublicValueStreamType = Vec<u8>;
pub type PublicValuesType = PublicValues<u32, u32>;
pub type CheckpointType = File;

pub fn generate_checkpoints(
    runtime: &mut Runtime,
) -> Result<(PublicValueStreamType, PublicValuesType, Vec<CheckpointType>), SP1CoreProverError> {
    // Execute the program, saving checkpoints at the start of every `shard_batch_size` cycle range.
    let create_checkpoints_span = tracing::debug_span!("create checkpoints").entered();
    let mut checkpoints = Vec::new();
    let (public_values_stream, public_values) = loop {
        // Execute the runtime until we reach a checkpoint.
        let (checkpoint, done) = runtime
            .execute_state()
            .map_err(SP1CoreProverError::ExecutionError)?;

        // Save the checkpoint to a temp file.
        let mut checkpoint_file = tempfile::tempfile().map_err(SP1CoreProverError::IoError)?;
        checkpoint
            .save(&mut checkpoint_file)
            .map_err(SP1CoreProverError::IoError)?;
        checkpoints.push(checkpoint_file);

        // If we've reached the final checkpoint, break out of the loop.
        if done {
            break (
                runtime.state.public_values_stream.clone(),
                runtime
                    .records
                    .last()
                    .expect("at least one record")
                    .public_values,
            );
        }
    };
    create_checkpoints_span.exit();

    Ok((public_values_stream, public_values, checkpoints))
}

pub fn prove_begin(
    args: ProveArgs,
) -> Result<(
    PublicValueStreamType,
    PublicValuesType,
    Vec<CheckpointType>,
    u64,
)> {
    let (client, stdin, pk, _) = common::init_client(args.clone());
    let (program, core_opts, context) = common::bootstrap(&client, &pk).unwrap();
    tracing::info!("Program size = {}", program.instructions.len());

    // Execute the program.
    let mut runtime = common::build_runtime(program, &stdin, core_opts, context);

    let (public_values_stream, public_values, checkpoints) =
        generate_checkpoints(&mut runtime).unwrap();

    Ok((
        public_values_stream,
        public_values,
        checkpoints,
        runtime.state.global_clk,
    ))
}

pub fn operator_phase1(
    args: ProveArgs,
    indexed_commitments: Vec<(u32, Vec<CommitmentPairType>)>,
    public_values_stream: Vec<u8>,
    cycles: u64,
) -> Result<SP1ProofWithPublicValues> {
    let (client, stdin, pk, vk) = common::init_client(args.clone());
    let (program, core_opts, context) = common::bootstrap(&client, &pk).unwrap();

    // Execute the program.
    let runtime = common::build_runtime(program, &stdin, core_opts, context);

    // Setup the machine.
    let (stark_pk, stark_vk) = client
        .prover
        .sp1_prover()
        .core_prover
        .setup(runtime.program.as_ref());

    let mut challenger = client.prover.sp1_prover().core_prover.config().challenger();
    stark_vk.observe_into(&mut challenger);

    let mut prev_idx = 0;
    let mut records = Vec::new();
    for (idx, commitment_pair) in indexed_commitments {
        if idx != 0 && idx != prev_idx + 1 {
            panic!("commitments must be indexed sequentially");
        }
        prev_idx = idx;

        for (commitment, record) in commitment_pair {
            client.prover.sp1_prover().core_prover.update(
                &mut challenger,
                commitment,
                &record.public_values::<BabyBear>()[0..client
                    .prover
                    .sp1_prover()
                    .core_prover
                    .machine()
                    .num_pv_elts()],
            );
            records.push(record);
        }
    }

    let mut shard_proofs = Vec::new();
    for record in records {
        let shard_proof = client
            .prover
            .sp1_prover()
            .core_prover
            .commit_and_open(&stark_pk, record, &mut challenger.clone())
            .unwrap();
        shard_proofs.push(shard_proof);
    }
    let proof = MachineProof { shard_proofs };

    tracing::info!(
        "summary: proofSize={}",
        bincode::serialize(&proof).unwrap().len(),
    );

    let public_values = SP1PublicValues::from(&public_values_stream);
    let sp1_core_proof = SP1CoreProof {
        proof: SP1CoreProofData(proof.shard_proofs),
        stdin: stdin.clone(),
        public_values,
        cycles,
    };

    let proof = SP1ProofWithPublicValues {
        proof: SP1Proof::Core(sp1_core_proof.proof.0),
        stdin: sp1_core_proof.stdin,
        public_values: sp1_core_proof.public_values,
        sp1_version: client.prover.version().to_string(),
    };

    client.verify(&proof, &vk).expect("failed to verify proof");
    tracing::info!("Successfully verified shard proofs!");

    Ok(proof)
}
