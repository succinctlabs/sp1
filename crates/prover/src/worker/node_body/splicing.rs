use std::sync::Arc;

use sp1_core_executor::{
    CycleResult, ExecutionError, Program, SP1CoreOpts, SplicedMinimalTrace, SplicingVMEnum,
};
use sp1_hypercube::air::{ShardBoundary, ShardRange};
use sp1_jit::{MinimalTrace, TraceChunkRaw, MERKLE_PAGE_WORDS};
use sp1_prover_types::{Artifact, ArtifactClient};
use tokio::{sync::mpsc, task::JoinSet};

use crate::worker::{
    controller::{ChunkPayload, MerkleProvingInput},
    CommonProverInput,
};

/// A task for splicing a trace into single shard chunks. Carries only what the
/// SplicingVM needs; the node body ([`super::SpliceChunkWorker`]) owns the
/// proving-side resources (proof senders, ids).
pub struct SplicingTask {
    pub program: Arc<Program>,
    pub chunk: TraceChunkRaw,
    pub num_deferred_proofs: usize,
    pub common_input_artifact: Artifact,
    pub opts: SP1CoreOpts,
    pub dirty_page_ids: Vec<u32>,
    pub dirty_page_final_contents: Vec<[u64; MERKLE_PAGE_WORDS]>,
}

/// Runs the SplicingVM over one trace chunk, streaming the chunk's core shard
/// cuts on `cuts_tx` and returning its [`MerkleProvingInput`].
#[derive(Debug, Clone)]
pub struct SplicingWorker<A: ArtifactClient> {
    artifact_client: A,
}

impl<A: ArtifactClient> SplicingWorker<A> {
    pub fn new(artifact_client: A) -> Self {
        Self { artifact_client }
    }

    /// Runs the SplicingVM over one trace chunk, streaming the chunk's core shard
    /// cuts on `cuts_tx` and returning its [`MerkleProvingInput`].
    pub async fn call_streaming(
        &self,
        input: SplicingTask,
        payload: Arc<ChunkPayload>,
        cuts_tx: mpsc::Sender<SendSpliceTask>,
    ) -> Result<MerkleProvingInput, ExecutionError> {
        let SplicingTask {
            program,
            chunk,
            common_input_artifact,
            num_deferred_proofs,
            opts,
            dirty_page_ids,
            dirty_page_final_contents,
        } = input;
        // Each cut goes directly to the caller's `cuts_tx`.
        let splicing_tx = cuts_tx;
        let (output_tx, output_rx) =
            tokio::sync::oneshot::channel::<sp1_core_executor::MerkleProvingPayload>();

        let mut join_set = JoinSet::<Result<(), ExecutionError>>::new();

        let common_prover_input = self
            .artifact_client
            .download::<CommonProverInput>(&common_input_artifact)
            .await
            .map_err(|e| {
                ExecutionError::Other(format!("error downloading common prover input: {}", e))
            })?;

        // Spawn the task that splices the trace.
        let span = tracing::debug_span!("splicing trace chunk");
        join_set.spawn_blocking(
            move || {
            let _guard = span.enter();
            let mut vm = SplicingVMEnum::new(&chunk, program.clone(),  common_prover_input.nonce, opts);

            // SAFETY: If `dirty_page_ids` is empty, then no memory access
            // are done in the chunk, so the `on_access` will never fire.
            vm.set_dirty_pages(&dirty_page_ids, &dirty_page_final_contents);

            let start_num_mem_reads = chunk.num_mem_reads();
            let start_clk = vm.clk();
            let mut end_clk : u64;
            let mut last_splice = SplicedMinimalTrace::new_full_trace(chunk.clone());
            let mut shard_index: u32 = 0;
                let mut boundary = ShardBoundary {
                    timestamp: start_clk,
                    deferred_proof: num_deferred_proofs as u64,
                };
            loop {
                tracing::debug!("starting new shard at clk: {} at pc: {}", vm.clk(), vm.pc());
                let cycle_result = vm.execute()?;
                let shard_data = vm.take_pending_shard()
                    .expect("SplicingVM produced no ShardData at shard boundary");
                match cycle_result {
                    CycleResult::ShardBoundary => {
                        // Note: Chunk implentations should always be cheap to clone.
                        if let Some(spliced) = vm.splice(chunk.clone()) {
                            tracing::debug!(global_clk = vm.global_clk(), pc = vm.pc(), num_mem_reads_left = vm.mem_reads_len(), clk = vm.clk(), "shard boundary");
                            // Get the end boundary of the shard.
                            end_clk = vm.clk();
                            let end = ShardBoundary {
                                timestamp: end_clk,
                                deferred_proof: num_deferred_proofs as u64,
                            };
                            // Get the range of the shard.
                            let range = (boundary..end).into();
                            // Update the boundary to the end of the shard.
                            boundary = end;

                            // Set the last splice clk.
                            last_splice.set_last_clk(vm.clk());
                            last_splice.set_last_mem_reads_idx(
                                start_num_mem_reads as usize - vm.mem_reads_len(),
                            );
                            let splice_to_send = std::mem::replace(&mut last_splice, spliced);
                            tracing::debug!(global_clk = vm.global_clk(), "sending spliced trace to splicing tx");
                            splicing_tx.blocking_send(SendSpliceTask {
                                chunk: splice_to_send,
                                range,
                                shard_index,
                                shard_data,
                            })
                                .map_err(|e| ExecutionError::Other(format!("error sending to splicing tx: {}", e)))?;
                            tracing::debug!(global_clk = vm.global_clk(), "spliced trace sent to splicing tx");
                            // Mid-stream shard sent — bump for the next.
                            shard_index += 1;
                        } else {
                            tracing::debug!(global_clk = vm.global_clk(), pc = vm.pc(), num_mem_reads_left = vm.mem_reads_len(), "trace ended");
                            // Get the end boundary of the shard.
                            end_clk = vm.clk();
                            let end = ShardBoundary {
                                timestamp: end_clk,
                                deferred_proof: num_deferred_proofs as u64,
                            };
                            // Get the range of the shard.
                            let range = (boundary..end).into();

                            last_splice.set_last_clk(vm.clk());
                            last_splice.set_last_mem_reads_idx(
                                start_num_mem_reads as usize - vm.mem_reads_len(),
                            );
                            tracing::debug!(global_clk = vm.global_clk(), "sending last splice to splicing tx");
                            // Final shard via trace-ended path. No bump
                            // after — we break out of the loop.
                            splicing_tx.blocking_send(SendSpliceTask {
                                chunk: last_splice,
                                range,
                                shard_index,
                                shard_data,
                            })
                                .map_err(|e| ExecutionError::Other(format!("error sending to splicing tx: {}", e)))?;
                            tracing::debug!(global_clk = vm.global_clk(), "last splice sent to splicing tx");
                            break;
                        }
                    }
                    CycleResult::Done(true) => {
                        tracing::debug!(global_clk = vm.global_clk(), "done cycle result");
                        last_splice.set_last_clk(vm.clk());
                        last_splice.set_last_mem_reads_idx(chunk.num_mem_reads() as usize);

                        // Get the end boundary of the shard.
                        end_clk = vm.clk();
                        let end = ShardBoundary {
                            timestamp: end_clk,
                            deferred_proof: num_deferred_proofs as u64,
                        };
                        // Get the range of the shard.
                        let range = (boundary..end).into();

                        tracing::debug!(global_clk = vm.global_clk(), "sending last splice to splicing tx");
                        // Send the last splice. Final shard via Done(true)
                        // — no bump after, we break out of the loop.
                        splicing_tx.blocking_send(SendSpliceTask {
                            chunk: last_splice,
                            range,
                            shard_index,
                            shard_data,
                        })
                            .map_err(|e| ExecutionError::Other(format!("error sending to splicing tx: {}", e)))?;
                        tracing::debug!(global_clk = vm.global_clk(), "last splice sent to splicing tx");
                        break;
                    }
                    CycleResult::Done(false) | CycleResult::TraceEnd => {
                        // Note: Trace ends get mapped to shard boundaries.
                        unreachable!("The executor should never return an imcomplete program without a shard boundary");
                    }
                }
            }
            let merkle_payload = vm.take_per_chunk_state().into_merkle_proving_payload();
            tracing::debug!(
                merkle_payload_pages = merkle_payload.page_ids.len(),
                "splicing chunk merkle outputs ready"
            );
            // Ship the merkle payload out of the spawn_blocking.
            let _ = output_tx.send(merkle_payload);
            drop(vm);
            Ok(())
           });

        // Wait for the tasks to finish and collect the errors.
        while let Some(result) = join_set.join_next().await {
            result
                .map_err(|e| ExecutionError::Other(format!("splicer task panicked: {}", e)))??;
        }

        // The splice spawn_blocking sends `merkle_payload` on `output_tx`
        // unconditionally before returning Ok. The join_set drain above
        // propagates any spawn_blocking Err / panic via `??`.
        let merkle_payload = output_rx.await.map_err(|e| {
            ExecutionError::Other(format!(
                "splicing thread closed output channel without sending: {e}"
            ))
        })?;
        Ok(MerkleProvingInput {
            chunk_idx: payload.chunk_idx,
            pre_chunk_snapshot: payload.pre_chunk_snapshot.clone(),
            prev_leaves: Arc::new(payload.prev_leaves.clone()),
            new_leaves: Arc::new(payload.new_leaves.clone()),
            payload: merkle_payload,
        })
    }
}

/// One core shard cut the SplicingVM produced for a chunk.
pub struct SendSpliceTask {
    pub chunk: SplicedMinimalTrace<TraceChunkRaw>,
    pub range: ShardRange,
    pub shard_index: u32,
    pub shard_data: sp1_core_executor::ShardData,
}
