use std::{borrow::Borrow, collections::BTreeMap, io, sync::Arc};

use crate::executor::trace_chunk;
use hashbrown::HashSet;
use thiserror::Error;

use slop_algebra::PrimeField32;
use slop_challenger::IopCtx;
use sp1_hypercube::{
    air::{MachineAir, PublicValues, PROOF_NONCE_NUM_WORDS},
    prover::{AirProver, PcsProof, ProvingKey, SimpleProver},
    Machine, MachineProof, MachineRecord, ShardContext,
};

use crate::io::SP1Stdin;
use sp1_core_executor::{SP1CoreOpts, SplitOpts};

use sp1_core_executor::{
    CompressedMemory, CycleResult, ExecutionError, ExecutionRecord, MinimalExecutor, Program,
    SP1Context, SplicedMinimalTrace, SplicingVM,
};
use sp1_jit::MinimalTrace;

/// Generate execution records from a program and inputs.
///
/// This function executes the program, splits execution into shards, and generates
/// execution records suitable for proving. Returns the records and total cycle count.
///
/// This is a test-only function that generates records sequentially for simplicity.
pub fn generate_records<F>(
    program: Arc<Program>,
    stdin: SP1Stdin,
    opts: SP1CoreOpts,
    proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
    machine: Machine<F, impl MachineAir<F, Record = ExecutionRecord>>,
) -> Result<(Vec<ExecutionRecord>, u64), SP1CoreProverError>
where
    F: PrimeField32,
{
    let split_opts = SplitOpts::new(&opts, program.instructions.len(), false);

    // Phase 1: Run MinimalExecutor to generate trace chunks
    let mut minimal_executor =
        MinimalExecutor::tracing(program.clone(), opts.minimal_trace_chunk_threshold);

    for buf in stdin.buffer {
        minimal_executor.with_input(&buf);
    }

    let mut trace_chunks = Vec::new();
    while let Some(chunk) = minimal_executor.execute_chunk() {
        trace_chunks.push(chunk);
    }

    // Phase 2: Splice chunks and trace them to generate records
    let mut all_records = Vec::new();
    let mut deferred =
        ExecutionRecord::new(program.clone(), proof_nonce, opts.global_dependencies_opt);
    let mut touched_addresses = HashSet::new();

    for chunk in trace_chunks {
        // Splice the chunk into shards
        let spliced_traces = splice_chunk_sequential(
            program.clone(),
            chunk,
            proof_nonce,
            opts.clone(),
            &mut touched_addresses,
        );

        // Trace each spliced chunk to generate execution records
        for (is_last, spliced) in spliced_traces {
            let record =
                ExecutionRecord::new(program.clone(), proof_nonce, opts.global_dependencies_opt);
            let (done, mut record, final_registers) =
                trace_chunk::<F>(program.clone(), opts.clone(), spliced, proof_nonce, record)
                    .map_err(SP1CoreProverError::ExecutionError)?;

            if done {
                // Insert global memory events for the last record
                minimal_executor.emit_globals(
                    &mut record,
                    final_registers,
                    touched_addresses.clone(),
                );
            }

            // Handle deferral
            deferred.append(&mut record.defer(&opts.retained_events_presets));
            let can_pack = done
                && record.estimated_trace_area <= split_opts.pack_trace_threshold
                && deferred.global_memory_initialize_events.len()
                    <= split_opts.combine_memory_threshold
                && deferred.global_memory_finalize_events.len()
                    <= split_opts.combine_memory_threshold
                && deferred.global_page_prot_initialize_events.len()
                    <= split_opts.combine_page_prot_threshold
                && deferred.global_page_prot_finalize_events.len()
                    <= split_opts.combine_page_prot_threshold;
            let deferred_records =
                deferred.split(done || is_last, &mut record, can_pack, &split_opts);

            // Generate dependencies and collect records
            let mut records = vec![record];
            records.extend(deferred_records);
            machine.generate_dependencies(records.iter_mut(), None);
            all_records.extend(records);
        }
    }

    let cycles = minimal_executor.global_clk();
    Ok((all_records, cycles))
}

/// Prove a program with the given inputs using SimpleProver.
///
/// This is a test-only function that proves records sequentially for simplicity. It is
/// extremely inefficient in both time and space, and should only be used for testing.
// #[allow(clippy::too_many_arguments)]
pub async fn prove_core<GC, SC, PC>(
    prover: &SimpleProver<GC, SC, PC>,
    pk: Arc<ProvingKey<GC, SC, PC>>,
    program: Arc<Program>,
    stdin: SP1Stdin,
    opts: SP1CoreOpts,
    context: SP1Context<'static>,
    machine: Machine<GC::F, SC::Air>,
) -> Result<(MachineProof<GC, PcsProof<GC, SC>>, u64), SP1CoreProverError>
where
    GC: IopCtx,
    SC: ShardContext<GC>,
    PC: AirProver<GC, SC>,
    GC::F: PrimeField32,
    SC::Air: MachineAir<GC::F, Record = ExecutionRecord>,
{
    let (all_records, cycles) =
        generate_records::<GC::F>(program, stdin, opts, context.proof_nonce, machine)?;

    // Prove records sequentially
    let mut shard_proofs = BTreeMap::new();
    for record in all_records {
        let proof = prover.prove_shard(pk.clone(), record).await;
        let public_values: &PublicValues<[GC::F; 4], [GC::F; 3], [GC::F; 4], GC::F> =
            proof.public_values.as_slice().borrow();
        shard_proofs.insert(
            (
                public_values.initial_timestamp,
                public_values.last_timestamp,
                public_values.previous_init_addr,
                public_values.previous_finalize_addr,
            ),
            proof,
        );
    }

    let shard_proofs = shard_proofs.into_values().collect();
    let proof = MachineProof { shard_proofs };

    Ok((proof, cycles))
}

/// Splice a trace chunk into shard-sized pieces sequentially.
/// Returns a vector of (is_last, spliced_trace) pairs.
fn splice_chunk_sequential(
    program: Arc<Program>,
    chunk: sp1_core_executor::TraceChunkRaw,
    proof_nonce: [u32; sp1_hypercube::air::PROOF_NONCE_NUM_WORDS],
    opts: SP1CoreOpts,
    touched_addresses: &mut HashSet<u64>,
) -> Vec<(bool, SplicedMinimalTrace<sp1_core_executor::TraceChunkRaw>)> {
    let mut result = Vec::new();
    let mut compressed_touched = CompressedMemory::new();
    let mut vm =
        SplicingVM::new(&chunk, program.clone(), &mut compressed_touched, proof_nonce, opts);

    let mut last_splice = SplicedMinimalTrace::new_full_trace(chunk.clone());
    let start_num_mem_reads = chunk.num_mem_reads();

    loop {
        match vm.execute().expect("splicing execution failed") {
            CycleResult::ShardBoundary => {
                if let Some(spliced) = vm.splice(chunk.clone()) {
                    last_splice.set_last_clk(vm.core.clk());
                    last_splice.set_last_mem_reads_idx(
                        start_num_mem_reads as usize - vm.core.mem_reads.len(),
                    );
                    let splice_to_emit = std::mem::replace(&mut last_splice, spliced);
                    result.push((false, splice_to_emit));
                } else {
                    last_splice.set_last_clk(vm.core.clk());
                    last_splice.set_last_mem_reads_idx(
                        start_num_mem_reads as usize - vm.core.mem_reads.len(),
                    );
                    result.push((true, last_splice));
                    break;
                }
            }
            CycleResult::Done(true) => {
                last_splice.set_last_clk(vm.core.clk());
                last_splice.set_last_mem_reads_idx(chunk.num_mem_reads() as usize);
                result.push((true, last_splice));
                break;
            }
            CycleResult::Done(false) | CycleResult::TraceEnd => {
                unreachable!("splicing should not return incomplete without shard boundary");
            }
        }
    }

    touched_addresses.extend(compressed_touched.is_set());
    result
}

#[derive(Error, Debug)]
pub enum SP1CoreProverError {
    #[error("failed to execute program: {0}")]
    ExecutionError(ExecutionError),
    #[error("io error: {0}")]
    IoError(io::Error),
    #[error("serialization error: {0}")]
    SerializationError(bincode::Error),
}
