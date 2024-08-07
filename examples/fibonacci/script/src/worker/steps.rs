use crate::common;
use crate::common::types::{ChallengerType, CommitmentType, RecordType};
use crate::ProveArgs;
use anyhow::Result;
use sp1_core::{
    air::PublicValues,
    runtime::ExecutionRecord,
    stark::{MachineProver, MachineRecord, ShardProof},
    utils::{reset_seek, trace_checkpoint, BabyBearPoseidon2},
};
use sp1_sdk::ExecutionReport;
use std::fs::File;

pub fn worker_phase1_impl(
    args: ProveArgs,
    idx: u32,
    checkpoint: &mut File,
    is_last_checkpoint: bool,
    public_values: PublicValues<u32, u32>,
) -> Result<(Vec<CommitmentType>, Vec<RecordType>)> {
    let (client, _, pk, _) = common::init_client(args);
    let (program, core_opts, _) = common::bootstrap(&client, &pk).unwrap();

    let mut deferred = ExecutionRecord::new(program.clone().into());
    let mut state = public_values.reset();
    let shards_in_checkpoint = core_opts.shard_batch_size as u32;
    state.shard = idx * shards_in_checkpoint;

    // Trace the checkpoint and reconstruct the execution records.
    let (mut records, report) = trace_checkpoint(program.clone(), checkpoint, core_opts);
    // Log some of the `ExecutionReport` information.
    tracing::info!(
        "execution report (totals): total_cycles={}, total_syscall_cycles={}",
        report.total_instruction_count(),
        report.total_syscall_count()
    );
    tracing::info!("execution report (opcode counts):");
    for line in ExecutionReport::sorted_table_lines(&report.opcode_counts) {
        tracing::info!("  {line}");
    }
    tracing::info!("execution report (syscall counts):");
    for line in ExecutionReport::sorted_table_lines(&report.syscall_counts) {
        tracing::info!("  {line}");
    }
    reset_seek(checkpoint);

    // Update the public values & prover state for the shards which contain "cpu events".
    for record in records.iter_mut() {
        state.shard += 1;
        state.execution_shard = record.public_values.execution_shard;
        state.start_pc = record.public_values.start_pc;
        state.next_pc = record.public_values.next_pc;
        record.public_values = state;
    }

    // Generate the dependencies.
    client
        .prover
        .sp1_prover()
        .core_prover
        .machine()
        .generate_dependencies(&mut records, &core_opts);

    // Defer events that are too expensive to include in every shard.
    for record in records.iter_mut() {
        deferred.append(&mut record.defer());
    }

    // See if any deferred shards are ready to be committed to.
    let mut deferred = deferred.split(is_last_checkpoint, core_opts.split_opts);

    // Update the public values & prover state for the shards which do not contain "cpu events"
    // before committing to them.
    if !is_last_checkpoint {
        state.execution_shard += 1;
    }

    for record in deferred.iter_mut() {
        state.shard += 1;
        state.previous_init_addr_bits = record.public_values.previous_init_addr_bits;
        state.last_init_addr_bits = record.public_values.last_init_addr_bits;
        state.previous_finalize_addr_bits = record.public_values.previous_finalize_addr_bits;
        state.last_finalize_addr_bits = record.public_values.last_finalize_addr_bits;
        state.start_pc = state.next_pc;
        record.public_values = state;
    }
    records.append(&mut deferred);

    // Committing to the shards.
    let commitments = records
        .iter()
        .map(|record| client.prover.sp1_prover().core_prover.commit(record))
        .collect::<Vec<_>>();

    Ok((commitments, records))
}

pub fn worker_phase2(
    args: ProveArgs,
    challenger: ChallengerType,
    records: Vec<RecordType>,
) -> Result<Vec<ShardProof<BabyBearPoseidon2>>> {
    let (client, stdin, pk, _) = common::init_client(args.clone());
    let (program, core_opts, context) = common::bootstrap(&client, &pk).unwrap();
    // Execute the program.
    let runtime = common::build_runtime(program, &stdin, core_opts, context);

    let (stark_pk, _) = client
        .prover
        .sp1_prover()
        .core_prover
        .setup(runtime.program.as_ref());

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

    Ok(shard_proofs)
}
