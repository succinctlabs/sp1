use std::{borrow::Borrow, collections::BTreeMap, io, sync::Arc};

use crate::executor::trace_chunk;
use crate::riscv::RiscvAir;
use thiserror::Error;

use slop_algebra::PrimeField32;
use slop_challenger::IopCtx;
use sp1_hypercube::{
    air::{PublicValues, PROOF_NONCE_NUM_WORDS},
    prover::{AirProver, PcsProof, ProvingKey, SimpleProver},
    MachineProof, ShardContext,
};

use crate::io::SP1Stdin;
use sp1_core_executor::{SP1CoreOpts, SplitOpts};

use sp1_core_executor::{
    CycleResult, ExecutionError, ExecutionRecord, Program, SP1Context, SplicedMinimalTrace,
    SplicingVMEnum,
};
use sp1_core_executor_runner::MinimalExecutorRunner;
use sp1_jit::{MinimalTrace, TraceChunk};

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
) -> Result<(Vec<ExecutionRecord>, u64), SP1CoreProverError>
where
    F: PrimeField32,
{
    let machine = RiscvAir::<F>::machine();
    let _split_opts = SplitOpts::new(&opts, program.instructions.len(), false);

    // Phase 1: Run MinimalExecutorRunner to generate trace chunks
    let mut minimal_executor = MinimalExecutorRunner::new(
        program.clone(),
        false,
        Some(opts.minimal_trace_chunk_threshold),
        opts.memory_limit,
        opts.trace_chunk_slots,
    );

    for buf in stdin.buffer {
        minimal_executor.with_input(&buf);
    }

    let mut trace_chunks = Vec::new();
    while let Some(chunk) = minimal_executor.try_execute_chunk()? {
        // Convert TraceChunkRaw to TraceChunk so we are sure to **own**
        // the memory. This avoids deadlock situation when shared memory
        // based chunk is used.
        let chunk: TraceChunk = chunk.into();
        trace_chunks.push(chunk);
    }

    // Phase 2: Splice chunks and trace them to generate records
    let mut all_records = Vec::new();

    for chunk in trace_chunks {
        // Splice the chunk into shards
        let spliced_traces =
            splice_chunk_sequential(program.clone(), chunk, proof_nonce, opts.clone());

        // Trace each spliced chunk to generate execution records
        for (_is_last, spliced) in spliced_traces {
            let record =
                ExecutionRecord::new(program.clone(), proof_nonce, opts.global_dependencies_opt);
            let (_done, record, _final_registers) =
                trace_chunk::<F>(program.clone(), opts.clone(), spliced, proof_nonce, record)
                    .map_err(SP1CoreProverError::ExecutionError)?;

            // Generate dependencies and collect records
            let mut records = vec![record];
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
pub async fn prove_core<GC, SC, PC>(
    prover: &SimpleProver<GC, SC, PC>,
    pk: Arc<ProvingKey<GC, SC, PC>>,
    program: Arc<Program>,
    stdin: SP1Stdin,
    opts: SP1CoreOpts,
    context: SP1Context<'static>,
) -> Result<(MachineProof<GC, PcsProof<GC, SC>>, u64), SP1CoreProverError>
where
    GC: IopCtx,
    SC: ShardContext<GC, Air = RiscvAir<GC::F>>,
    PC: AirProver<GC, SC>,
    GC::F: PrimeField32,
{
    let (all_records, cycles) =
        generate_records::<GC::F>(program, stdin, opts, context.proof_nonce)?;

    // Prove records sequentially
    let mut shard_proofs = BTreeMap::new();
    for record in all_records {
        let proof = prover.prove_shard(pk.clone(), record).await;
        let public_values: &PublicValues<[GC::F; 4], [GC::F; 3], [GC::F; 4], GC::F> =
            proof.public_values.as_slice().borrow();
        shard_proofs.insert((public_values.initial_timestamp, public_values.last_timestamp), proof);
    }

    let shard_proofs = shard_proofs.into_values().collect();
    let proof = MachineProof { shard_proofs };

    Ok((proof, cycles))
}

/// Splice a trace chunk into shard-sized pieces sequentially.
/// Returns a vector of (is_last, spliced_trace) pairs.
fn splice_chunk_sequential<T: MinimalTrace>(
    program: Arc<Program>,
    chunk: T,
    proof_nonce: [u32; sp1_hypercube::air::PROOF_NONCE_NUM_WORDS],
    opts: SP1CoreOpts,
) -> Vec<(bool, SplicedMinimalTrace<T>)> {
    let mut result = Vec::new();
    let mut vm = SplicingVMEnum::new(&chunk, program.clone(), proof_nonce, opts);

    let mut last_splice = SplicedMinimalTrace::new_full_trace(chunk.clone());
    let start_num_mem_reads = chunk.num_mem_reads();

    loop {
        match vm.execute().expect("splicing execution failed") {
            CycleResult::ShardBoundary => {
                if let Some(spliced) = vm.splice(chunk.clone()) {
                    last_splice.set_last_clk(vm.clk());
                    last_splice
                        .set_last_mem_reads_idx(start_num_mem_reads as usize - vm.mem_reads_len());
                    let splice_to_emit = std::mem::replace(&mut last_splice, spliced);
                    result.push((false, splice_to_emit));
                } else {
                    last_splice.set_last_clk(vm.clk());
                    last_splice
                        .set_last_mem_reads_idx(start_num_mem_reads as usize - vm.mem_reads_len());
                    result.push((true, last_splice));
                    break;
                }
            }
            CycleResult::Done(true) => {
                last_splice.set_last_clk(vm.clk());
                last_splice.set_last_mem_reads_idx(chunk.num_mem_reads() as usize);
                result.push((true, last_splice));
                break;
            }
            CycleResult::Done(false) | CycleResult::TraceEnd => {
                unreachable!("splicing should not return incomplete without shard boundary");
            }
        }
    }

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

impl From<ExecutionError> for SP1CoreProverError {
    fn from(e: ExecutionError) -> SP1CoreProverError {
        SP1CoreProverError::ExecutionError(e)
    }
}
