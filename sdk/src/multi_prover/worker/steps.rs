use crate::multi_prover::common;
use crate::multi_prover::common::memory_layouts::{
    SerializableDeferredLayout, SerializableRecursionLayout, SerializableReduceLayout,
};
use crate::multi_prover::common::types::{
    ChallengerType, CommitmentType, DeferredLayout, RecordType, RecursionLayout, ReduceLayout,
};
use crate::multi_prover::common::ProveArgs;
use anyhow::Result;
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sp1_core::air::Word;
use sp1_core::runtime::ExecutionReport;
use sp1_core::{
    air::PublicValues,
    runtime::ExecutionRecord,
    stark::{MachineProver, MachineRecord, ShardProof},
    utils::{reset_seek, trace_checkpoint, BabyBearPoseidon2},
};
use sp1_prover::ReduceProgramType;
use std::fs::File;

pub fn worker_commit_checkpoint_impl<T: Serialize + DeserializeOwned>(
    args: &ProveArgs<T>,
    idx: u32,
    checkpoint: &mut File,
    is_last_checkpoint: bool,
    public_values: PublicValues<u32, u32>,
) -> Result<(Vec<CommitmentType>, Vec<RecordType>)> {
    let (client, _, pk, _) = common::init_client(args);
    let (program, opts, _) = common::bootstrap(&client, &pk).unwrap();

    let mut deferred = ExecutionRecord::new(program.clone().into());
    let mut state = public_values.reset();
    let shards_in_checkpoint = opts.core_opts.shard_batch_size as u32;
    state.shard = idx * shards_in_checkpoint;

    // Trace the checkpoint and reconstruct the execution records.
    let (mut records, report) = trace_checkpoint(program.clone(), checkpoint, opts.core_opts);
    // Log some of the `ExecutionReport` information.
    tracing::debug!(
        "execution report (totals): total_cycles={}, total_syscall_cycles={}",
        report.total_instruction_count(),
        report.total_syscall_count()
    );
    tracing::debug!("execution report (opcode counts):");
    for line in ExecutionReport::sorted_table_lines(&report.opcode_counts) {
        tracing::debug!("  {line}");
    }
    tracing::debug!("execution report (syscall counts):");
    for line in ExecutionReport::sorted_table_lines(&report.syscall_counts) {
        tracing::debug!("  {line}");
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
        .generate_dependencies(&mut records, &opts.core_opts);

    // Defer events that are too expensive to include in every shard.
    for record in records.iter_mut() {
        deferred.append(&mut record.defer());
    }

    // See if any deferred shards are ready to be committed to.
    let mut deferred = deferred.split(is_last_checkpoint, opts.core_opts.split_opts);

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

pub fn worker_prove_checkpoint_impl<T: Serialize + DeserializeOwned>(
    args: &ProveArgs<T>,
    challenger: ChallengerType,
    records: Vec<RecordType>,
) -> Result<Vec<ShardProof<BabyBearPoseidon2>>> {
    let (client, stdin, pk, _) = common::init_client(&args);
    let (program, opts, context) = common::bootstrap(&client, &pk).unwrap();
    // Execute the program.
    let runtime = common::build_runtime(program, &stdin, opts, context);

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

pub fn worker_compress_proofs_for_recursion<T: Serialize + DeserializeOwned>(
    args: &ProveArgs<T>,
    mut layout: SerializableRecursionLayout,
) -> Result<(ShardProof<BabyBearPoseidon2>, ReduceProgramType)> {
    let (client, stdin, pk, _) = common::init_client(&args);
    let (program, opts, context) = common::bootstrap(&client, &pk).unwrap();
    let runtime = common::build_runtime(program, &stdin, opts, context);
    let (_, stark_vk) = client
        .prover
        .sp1_prover()
        .core_prover
        .setup(runtime.program.as_ref());

    let sp1_prover = client.prover.sp1_prover();
    let leaf_challenger = layout
        .leaf_challenger
        .to_challenger(&sp1_prover.core_prover.config().perm);
    let initial_reconstruct_challenger = layout
        .initial_reconstruct_challenger
        .to_challenger(&sp1_prover.core_prover.config().perm);

    let input = RecursionLayout {
        vk: &stark_vk,
        machine: sp1_prover.core_prover.machine(),
        shard_proofs: layout.shard_proofs,
        leaf_challenger: &leaf_challenger,
        initial_reconstruct_challenger,
        is_complete: layout.is_complete,
    };

    sp1_prover
        .compress_machine_proof(
            input,
            &sp1_prover.recursion_program,
            &sp1_prover.rec_pk,
            opts,
        )
        .map(|p| (p, ReduceProgramType::Core))
        .map_err(|e| anyhow::anyhow!("failed to compress machine proof: {:?}", e))
}

pub fn worker_compress_proofs_for_deferred<T: Serialize + DeserializeOwned>(
    args: &ProveArgs<T>,
    mut layout: SerializableDeferredLayout,
    last_proof_pv: PublicValues<Word<BabyBear>, BabyBear>,
) -> Result<(ShardProof<BabyBearPoseidon2>, ReduceProgramType)> {
    let (client, stdin, pk, _) = common::init_client(&args);
    let (program, opts, context) = common::bootstrap(&client, &pk).unwrap();
    let runtime = common::build_runtime(program, &stdin, opts, context);
    let (_, stark_vk) = client
        .prover
        .sp1_prover()
        .core_prover
        .setup(runtime.program.as_ref());

    let sp1_prover = client.prover.sp1_prover();

    let leaf_challenger = layout
        .leaf_challenger
        .to_challenger(&sp1_prover.core_prover.config().perm);
    let input = DeferredLayout {
        compress_vk: &sp1_prover.compress_vk,
        machine: sp1_prover.compress_prover.machine(),
        proofs: layout.proofs,
        start_reconstruct_deferred_digest: layout.start_reconstruct_deferred_digest,
        is_complete: false,
        sp1_vk: &stark_vk,
        sp1_machine: sp1_prover.core_prover.machine(),
        end_pc: BabyBear::zero(),
        end_shard: last_proof_pv.shard + BabyBear::one(),
        end_execution_shard: last_proof_pv.execution_shard,
        init_addr_bits: last_proof_pv.last_init_addr_bits,
        finalize_addr_bits: last_proof_pv.last_finalize_addr_bits,
        leaf_challenger: leaf_challenger,
        committed_value_digest: last_proof_pv.committed_value_digest.to_vec(),
        deferred_proofs_digest: last_proof_pv.deferred_proofs_digest.to_vec(),
    };

    sp1_prover
        .compress_machine_proof(
            input,
            &sp1_prover.recursion_program,
            &sp1_prover.rec_pk,
            opts,
        )
        .map(|p| (p, ReduceProgramType::Deferred))
        .map_err(|e| anyhow::anyhow!("failed to compress machine proof: {:?}", e))
}

pub fn worker_compress_proofs_for_reduce<T: Serialize + DeserializeOwned>(
    args: &ProveArgs<T>,
    layout: SerializableReduceLayout,
) -> Result<(ShardProof<BabyBearPoseidon2>, ReduceProgramType)> {
    let (client, _, pk, _) = common::init_client(&args);
    let (_, opts, _) = common::bootstrap(&client, &pk).unwrap();

    let sp1_prover = client.prover.sp1_prover();

    let input = ReduceLayout {
        compress_vk: &sp1_prover.compress_vk,
        recursive_machine: sp1_prover.compress_prover.machine(),
        shard_proofs: layout.shard_proofs,
        kinds: layout.kinds,
        is_complete: layout.is_complete,
    };

    sp1_prover
        .compress_machine_proof(
            input,
            &sp1_prover.compress_program,
            &sp1_prover.compress_pk,
            opts,
        )
        .map(|p| (p, ReduceProgramType::Reduce))
        .map_err(|e| anyhow::anyhow!("failed to compress machine proof: {:?}", e))
}
