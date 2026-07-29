use std::{io, sync::Arc};

use crate::executor::trace_chunk;
use crate::merkle_prover::{
    build_merkle_proof_record, split_merkle_proof_record, LeafState, MerkleProvingInput,
};
use crate::riscv::RiscvAir;
use thiserror::Error;

use slop_algebra::PrimeField32;
use slop_challenger::IopCtx;
use sp1_hypercube::{
    air::PROOF_NONCE_NUM_WORDS,
    prover::{AirProver, PcsProof, ProvingKey, SimpleProver},
    MachineProof, ShardContext,
};

use crate::io::SP1Stdin;
use sp1_core_executor::SP1CoreOpts;

use sp1_core_executor::{
    CycleResult, ExecutionError, ExecutionRecord, MerkleProvingPayload, Program, SP1Context,
    ShardData, SplicedMinimalTrace, SplicingVMEnum, SHARD_KIND_EXECUTION, SHARD_KIND_MERKLE,
};
use sp1_core_executor_runner::MinimalExecutorRunner;
use sp1_jit::{DirtyPages, MinimalTrace, TraceChunk, MERKLE_PAGE_WORDS};

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

    // Phase 1: Run MinimalExecutorRunner to generate trace chunks.
    let dirty_pages_slot_bytes: usize = 256 * 1024 * 1024;
    let mut minimal_executor = MinimalExecutorRunner::new_with_dirty_pages(
        program.clone(),
        false,
        Some(opts.minimal_trace_chunk_threshold),
        opts.memory_limit,
        opts.trace_chunk_slots,
        Some(dirty_pages_slot_bytes),
    );

    for buf in stdin.buffer {
        minimal_executor.with_input(&buf);
    }

    let mut trace_chunks = Vec::new();
    while let Some((chunk, dirty_pages)) = minimal_executor.try_execute_chunk_with_dirty_pages()? {
        // Convert TraceChunkRaw to TraceChunk so we are sure to **own**
        // the memory. This avoids deadlock situation when shared memory
        // based chunk is used.
        let chunk: TraceChunk = chunk.into();
        trace_chunks.push((chunk, dirty_pages));
    }

    // Phase 2: Splice chunks and trace them to generate records.
    let mut leaf_state = LeafState::from_memory_image(&program.memory_image);
    let mut all_records = Vec::new();

    for (chunk_idx, (chunk, dirty_pages)) in trace_chunks.into_iter().enumerate() {
        let chunk_pc_start = chunk.pc_start;

        // Leaf bookkeeping, mirroring the controller's leaf-hash worker.
        let pre_chunk_snapshot = leaf_state.snapshot();
        let (prev_leaves, new_leaves) = leaf_state.ingest_chunk(&dirty_pages.pages);

        // Splice the chunk into shards.
        let (spliced_traces, merkle_payload) =
            splice_chunk_sequential(program.clone(), chunk, dirty_pages, proof_nonce, opts.clone());

        // Build the chunk's batch merkle proof and its merkle-shard record.
        let proof_record = build_merkle_proof_record(MerkleProvingInput {
            chunk_idx: chunk_idx as u64,
            pre_chunk_snapshot,
            prev_leaves: Arc::new(prev_leaves),
            new_leaves: Arc::new(new_leaves),
            payload: merkle_payload,
        });
        let prev_root = proof_record.proof.prev_root.map(|x| x.as_canonical_u32());
        let cur_root = proof_record.proof.cur_root.map(|x| x.as_canonical_u32());

        // Merkle shards: head of the chunk, non-execution; only shard 0 sets is_first_merkle_shard.
        let merkle_pieces =
            split_merkle_proof_record(proof_record, program.instructions.len(), &opts);
        let num_merkle_shards = merkle_pieces.len() as u32;
        let mut chunk_records: Vec<ExecutionRecord> = merkle_pieces
            .into_iter()
            .enumerate()
            .map(|(merkle_index, piece)| {
                let mut record = ExecutionRecord::from_merkle_proof_record(
                    program.clone(),
                    proof_nonce,
                    opts.global_dependencies_opt,
                    piece,
                );
                record.public_values.update_initialized_state(
                    chunk_pc_start,
                    program.enable_untrusted_programs,
                    program.trap_context,
                    program.untrusted_memory,
                );
                record.shard_kind = SHARD_KIND_MERKLE;
                record.shard_index = merkle_index as u32;
                record.public_values.is_execution_shard = 0;
                record
            })
            .collect();

        // Then the chunk's execution shards.
        for (exec_index, (_is_last, spliced, shard_data)) in spliced_traces.into_iter().enumerate()
        {
            let record = match shard_data {
                Some(shard_data) => ExecutionRecord::from_shard_data(
                    program.clone(),
                    proof_nonce,
                    opts.global_dependencies_opt,
                    shard_data,
                ),
                None => {
                    ExecutionRecord::new(program.clone(), proof_nonce, opts.global_dependencies_opt)
                }
            };
            let (_done, mut record, _final_registers) =
                trace_chunk::<F>(program.clone(), opts.clone(), spliced, proof_nonce, record)
                    .map_err(SP1CoreProverError::ExecutionError)?;
            record.shard_kind = SHARD_KIND_EXECUTION;
            record.shard_index = num_merkle_shards + exec_index as u32;
            record.public_values.is_execution_shard = 1;
            chunk_records.push(record);
        }
        let num_execution_shards = (chunk_records.len() - num_merkle_shards as usize) as u32;

        if chunk_idx == 0 {
            chunk_records[0].public_values.is_first_shard = 1;
        }
        // Chunk metadata + the chunk's bracketing merkle roots, on every shard.
        for record in chunk_records.iter_mut() {
            record.trace_chunk_idx = chunk_idx as u32;
            record.num_execution_shards = num_execution_shards;
            record.num_merkle_shards = num_merkle_shards;
            record.prev_root = prev_root;
            record.cur_root = cur_root;
            record.public_values.prev_merkle_root = prev_root;
            record.public_values.merkle_root = cur_root;
            record.public_values.trace_chunk_idx = record.trace_chunk_idx;
            record.public_values.shard_index = record.shard_index;
            record.public_values.num_execution_shard = num_execution_shards;
            record.public_values.num_merkle_shard = num_merkle_shards;
            record.finalize_public_values::<F>();
        }

        // Dependencies last: the pv-driven byte/range lookups must see the final pvs.
        machine.generate_dependencies(chunk_records.iter_mut(), None);
        all_records.extend(chunk_records);
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

    // Prove records sequentially in generation order: per chunk the merkle shard first
    // (`order_commitments` ranks merkle before core), then the execution shards.
    let mut shard_proofs = Vec::new();
    for record in all_records {
        let proof = prover.prove_shard(pk.clone(), record).await;
        shard_proofs.push(proof);
    }

    let proof = MachineProof { shard_proofs };

    Ok((proof, cycles))
}

/// Splice a trace chunk into shard-sized pieces sequentially.
/// Returns a vector of (is_last, spliced_trace, shard_data) triples plus the chunk's
/// reconstructed touched-page payload for merkle proving.
#[allow(clippy::type_complexity)]
fn splice_chunk_sequential<T: MinimalTrace>(
    program: Arc<Program>,
    chunk: T,
    dirty_pages: DirtyPages,
    proof_nonce: [u32; sp1_hypercube::air::PROOF_NONCE_NUM_WORDS],
    opts: SP1CoreOpts,
) -> (Vec<(bool, SplicedMinimalTrace<T>, Option<ShardData>)>, MerkleProvingPayload) {
    let mut result = Vec::new();
    let mut vm = SplicingVMEnum::new(&chunk, program.clone(), proof_nonce, opts);

    // Set the dirty page information.
    let page_ids: Vec<u32> = dirty_pages.pages.iter().map(|p| p.page_id).collect();
    let final_contents: Vec<[u64; MERKLE_PAGE_WORDS]> =
        dirty_pages.pages.iter().map(|p| p.final_contents).collect();
    vm.set_dirty_pages(&page_ids, &final_contents);

    let mut last_splice = SplicedMinimalTrace::new_full_trace(chunk.clone());
    let start_num_mem_reads = chunk.num_mem_reads();

    loop {
        let cycle_result = vm.execute().expect("splicing execution failed");
        let shard_data = vm.take_pending_shard();
        match cycle_result {
            CycleResult::ShardBoundary => {
                if let Some(spliced) = vm.splice(chunk.clone()) {
                    last_splice.set_last_clk(vm.clk());
                    last_splice
                        .set_last_mem_reads_idx(start_num_mem_reads as usize - vm.mem_reads_len());
                    let splice_to_emit = std::mem::replace(&mut last_splice, spliced);
                    result.push((false, splice_to_emit, shard_data));
                } else {
                    last_splice.set_last_clk(vm.clk());
                    last_splice
                        .set_last_mem_reads_idx(start_num_mem_reads as usize - vm.mem_reads_len());
                    result.push((true, last_splice, shard_data));
                    break;
                }
            }
            CycleResult::Done(true) => {
                last_splice.set_last_clk(vm.clk());
                last_splice.set_last_mem_reads_idx(chunk.num_mem_reads() as usize);
                result.push((true, last_splice, shard_data));
                break;
            }
            CycleResult::Done(false) | CycleResult::TraceEnd => {
                unreachable!("splicing should not return incomplete without shard boundary");
            }
        }
    }

    // The chunk has fully executed; hand its merkle reconstruction payload out.
    let merkle_payload = vm.take_per_chunk_state().into_merkle_proving_payload();
    (result, merkle_payload)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::test_util::{
        accumulate_interactions, accumulate_public_value_interactions, chip_traces, BusTotals,
    };
    use crate::programs::tests::fibonacci_program;
    use slop_algebra::{AbstractField, Field};
    use sp1_hypercube::air::InteractionScope;
    use sp1_hypercube::InteractionKind;
    use sp1_primitives::SP1Field;

    /// Generate records for `program` with the given chunk threshold and group them by chunk.
    fn chunked_records(
        program: Arc<Program>,
        minimal_trace_chunk_threshold: u64,
    ) -> Vec<Vec<ExecutionRecord>> {
        let opts = SP1CoreOpts { minimal_trace_chunk_threshold, ..Default::default() };
        let (records, _cycles) =
            generate_records::<SP1Field>(program, SP1Stdin::new(), opts, [0; 4]).unwrap();
        let num_chunks = records.iter().map(|r| r.trace_chunk_idx).max().unwrap() + 1;
        let mut chunks: Vec<Vec<ExecutionRecord>> = (0..num_chunks).map(|_| Vec::new()).collect();
        for record in records {
            chunks[record.trace_chunk_idx as usize].push(record);
        }
        chunks
    }

    #[test]
    fn test_generate_records_merkle_chunks() {
        let program = Arc::new(fibonacci_program());
        // Small chunk threshold (in `MemValue`s) so the program splits into several chunks,
        // exercising the cross-chunk leaf-state chaining and non-trivial `pre_chunk_snapshot`s.
        let chunks = chunked_records(program, 1 << 9);
        assert!(chunks.len() >= 2, "expected a multi-chunk execution, got {}", chunks.len());

        let machine = RiscvAir::<SP1Field>::machine();
        let mut prev_chunk_root: Option<[u32; 8]> = None;
        for (chunk_idx, chunk) in chunks.iter().enumerate() {
            // Structure: exactly one merkle shard, then the execution shards in order.
            let (merkle, execution) = chunk.split_first().expect("chunk has no records");
            assert!(!execution.is_empty(), "chunk {chunk_idx} has no execution shards");
            assert_eq!(merkle.shard_kind, SHARD_KIND_MERKLE);
            assert_eq!(merkle.num_merkle_shards, 1);
            assert_eq!(merkle.public_values.is_execution_shard, 0);
            assert!(merkle.merkle_proof_record.is_some());

            let first_exec = &execution[0];
            assert_eq!(merkle.public_values.pc_start, first_exec.public_values.pc_start);
            assert_eq!(merkle.public_values.pc_start, merkle.public_values.next_pc);
            assert_eq!(merkle.public_values.initial_timestamp, 1);
            assert_eq!(merkle.public_values.last_timestamp, 1);
            assert_eq!(merkle.public_values.num_merkle_shard, 1);
            assert_eq!(merkle.public_values.num_execution_shard, execution.len() as u32);

            assert_eq!(
                merkle.public_values.committed_value_digest,
                merkle.public_values.prev_committed_value_digest
            );
            assert_eq!(
                merkle.public_values.deferred_proofs_digest,
                merkle.public_values.prev_deferred_proofs_digest
            );
            assert_eq!(merkle.public_values.exit_code, merkle.public_values.prev_exit_code);
            assert_eq!(
                merkle.public_values.commit_syscall,
                merkle.public_values.prev_commit_syscall
            );
            assert_eq!(
                merkle.public_values.commit_deferred_syscall,
                merkle.public_values.prev_commit_deferred_syscall
            );

            for (i, record) in execution.iter().enumerate() {
                assert_eq!(record.shard_kind, SHARD_KIND_EXECUTION);
                assert_eq!(record.shard_index, 1 + i as u32);
                assert_eq!(record.num_execution_shards, execution.len() as u32);
                assert_eq!(record.public_values.is_execution_shard, 1);
                assert_eq!(record.public_values.num_execution_shard, execution.len() as u32);
                assert_eq!(record.public_values.num_merkle_shard, 1);
            }

            // Every shard of the chunk carries the chunk's bracketing roots.
            for record in chunk {
                assert_eq!(record.prev_root, merkle.prev_root);
                assert_eq!(record.cur_root, merkle.cur_root);
                assert_eq!(record.public_values.prev_merkle_root, merkle.prev_root);
                assert_eq!(record.public_values.merkle_root, merkle.cur_root);
            }

            // The merkle roots chain across chunks.
            if let Some(prev) = prev_chunk_root {
                assert_eq!(
                    merkle.prev_root, prev,
                    "chunk {chunk_idx} prev_root does not chain from the previous chunk"
                );
            }
            prev_chunk_root = Some(merkle.cur_root);

            // The Global-scope bus balances within the chunk: the execution shards'
            // memory init/finalize messages cancel against the merkle shard's page
            // contents, and the merkle-root pv interactions cancel against the
            // tree-traversal chip. The Local-scope bus balances within each record
            // (checked for the kinds whose interactions don't reference preprocessed
            // columns — `accumulate_interactions` passes an empty preprocessed row).
            let kinds = [
                InteractionKind::Memory,
                InteractionKind::State,
                InteractionKind::Syscall,
                InteractionKind::MerkleTreeTraversal,
                InteractionKind::LeafHash,
            ];
            let mut chunk_totals = BusTotals::new();
            for (record_idx, record) in chunk.iter().enumerate() {
                let mut totals = BusTotals::new();
                for chip in machine.chips().iter().filter(|chip| chip.included(record)) {
                    let (global, main) = chip_traces(chip, record);
                    accumulate_interactions(
                        chip,
                        global.as_ref(),
                        main.as_ref(),
                        &kinds,
                        &mut totals,
                    );
                }
                accumulate_public_value_interactions(record, &kinds, &mut totals);
                let unbalanced_local: Vec<_> = totals
                    .iter()
                    .filter(|((scope, _, _), net)| {
                        *scope == InteractionScope::Local && !net.is_zero()
                    })
                    .map(|(key, net)| (key.clone(), *net))
                    .collect();
                assert!(
                    unbalanced_local.is_empty(),
                    "chunk {chunk_idx} record {record_idx} local bus is unbalanced; \
                     {} nonzero nets, first 5: {:?}",
                    unbalanced_local.len(),
                    &unbalanced_local[..unbalanced_local.len().min(5)]
                );
                for (key, net) in totals {
                    *chunk_totals.entry(key).or_insert(SP1Field::zero()) += net;
                }
            }
            let unbalanced: Vec<_> = chunk_totals
                .iter()
                .filter(|((scope, _, _), net)| *scope == InteractionScope::Global && !net.is_zero())
                .map(|(key, net)| (key.clone(), *net))
                .collect();
            assert!(
                unbalanced.is_empty(),
                "chunk {chunk_idx} global bus is unbalanced; {} nonzero nets, first 5: {:?}",
                unbalanced.len(),
                &unbalanced[..unbalanced.len().min(5)]
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_core_e2e_prove_with_merkle_shards() {
        use slop_basefold::FriConfig;
        use sp1_hypercube::{
            air::PublicValues, prover::simple_prover, MachineVerifier, ShardVerifier,
        };
        use std::borrow::Borrow;

        let program = Arc::new(fibonacci_program());
        let verifier = ShardVerifier::from_basefold_parameters(
            FriConfig::default_fri_config(),
            21,
            22,
            RiscvAir::machine(),
        );
        let prover = simple_prover(verifier.clone());
        let (pk, vk) = prover.setup(program.clone()).await;
        let pk = unsafe { pk.into_inner() };

        // Small chunk threshold so the proof spans several chunks (and merkle shards).
        let opts = SP1CoreOpts { minimal_trace_chunk_threshold: 1 << 9, ..Default::default() };
        let (proof, _) =
            prove_core(&prover, pk, program, SP1Stdin::new(), opts, SP1Context::default())
                .await
                .unwrap();

        // Every shard proof carries the global round outputs.
        for shard_proof in &proof.shard_proofs {
            assert!(shard_proof.global_commitment.is_some());
            assert!(shard_proof.global_cumulative_sum.is_some());
        }

        // One merkle shard per chunk, and the chunks' merkle roots chain.
        let merkle_pvs: Vec<PublicValues<[SP1Field; 4], [SP1Field; 3], [SP1Field; 4], SP1Field>> =
            proof
                .shard_proofs
                .iter()
                .map(|p| {
                    let pv: &PublicValues<[SP1Field; 4], [SP1Field; 3], [SP1Field; 4], SP1Field> =
                        p.public_values.as_slice().borrow();
                    *pv
                })
                .filter(|pv| pv.is_execution_shard == SP1Field::zero())
                .collect();
        assert!(merkle_pvs.len() >= 2, "expected merkle shards from several chunks");
        for pair in merkle_pvs.windows(2) {
            assert_eq!(pair[0].merkle_root, pair[1].prev_merkle_root);
        }

        // Every shard — execution and merkle — verifies natively.
        let machine_verifier = MachineVerifier::new(verifier);
        machine_verifier.verify(&vk, &proof).expect("core e2e proof should verify");
    }
}
