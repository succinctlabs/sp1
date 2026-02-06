use std::sync::Arc;

use futures::{stream::FuturesUnordered, StreamExt};
use slop_futures::pipeline::{AsyncEngine, AsyncWorker, Pipeline};
use sp1_core_executor::{
    CompressedMemory, CycleResult, ExecutionError, Program, SP1CoreOpts, SplicedMinimalTrace,
    SplicingVM,
};
use sp1_hypercube::air::{ShardBoundary, ShardRange};
use sp1_jit::{MinimalTrace, TraceChunkRaw};
use sp1_prover_types::{await_blocking, Artifact, ArtifactClient};
use tokio::{sync::mpsc, task::JoinSet};
use tracing::Instrument;

use crate::worker::{
    controller::create_core_proving_task, CommonProverInput, DeferredMessage, FinalVmState,
    FinalVmStateLock, ProofData, SpawnProveOutput, TaskContext, TouchedAddresses, TraceData,
    WorkerClient,
};

pub type SplicingEngine<A, W> =
    AsyncEngine<SplicingTask, Result<(), ExecutionError>, SplicingWorker<A, W>>;

/// A task for splicing a trace into single shard chunks.
pub struct SplicingTask {
    pub program: Arc<Program>,
    pub chunk: TraceChunkRaw,
    pub elf_artifact: Artifact,
    pub num_deferred_proofs: usize,
    pub common_input_artifact: Artifact,
    pub all_touched_addresses: TouchedAddresses,
    pub final_vm_state: FinalVmStateLock,
    pub prove_shard_tx: mpsc::UnboundedSender<ProofData>,
    pub context: TaskContext,
    pub opts: SP1CoreOpts,
    pub deferred_marker_tx: mpsc::UnboundedSender<DeferredMessage>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SplicingWorker<A, W> {
    artifact_client: A,
    worker_client: W,
    number_of_send_splice_workers: usize,
    send_splice_input_buffer_size: usize,
}

impl<A, W> SplicingWorker<A, W>
where
    A: ArtifactClient,
    W: WorkerClient,
{
    pub fn new(
        artifact_client: A,
        worker_client: W,
        number_of_send_splice_workers: usize,
        send_splice_input_buffer_size: usize,
    ) -> Self {
        Self {
            artifact_client,
            worker_client,
            number_of_send_splice_workers,
            send_splice_input_buffer_size,
        }
    }

    fn initialize_send_splice_engine(
        &self,
        elf_artifact: Artifact,
        common_input_artifact: Artifact,
        context: TaskContext,
        prove_shard_tx: mpsc::UnboundedSender<ProofData>,
        deferred_marker_tx: mpsc::UnboundedSender<DeferredMessage>,
    ) -> SendSpliceEngine<A, W> {
        let workers = (0..self.number_of_send_splice_workers)
            .map(|_| SendSpliceWorker {
                artifact_client: self.artifact_client.clone(),
                worker_client: self.worker_client.clone(),
                elf_artifact: elf_artifact.clone(),
                common_input_artifact: common_input_artifact.clone(),
                context: context.clone(),
                prove_shard_tx: prove_shard_tx.clone(),
                deferred_marker_tx: deferred_marker_tx.clone(),
            })
            .collect();
        let input_buffer_size = self.send_splice_input_buffer_size;
        SendSpliceEngine::new(workers, input_buffer_size)
    }
}

impl<A, W> AsyncWorker<SplicingTask, Result<(), ExecutionError>> for SplicingWorker<A, W>
where
    A: ArtifactClient,
    W: WorkerClient,
{
    async fn call(&self, input: SplicingTask) -> Result<(), ExecutionError> {
        let SplicingTask {
            program,
            chunk,
            all_touched_addresses,
            final_vm_state,
            elf_artifact,
            common_input_artifact,
            num_deferred_proofs,
            prove_shard_tx,
            context,
            deferred_marker_tx,
            opts,
        } = input;
        let (splicing_tx, mut splicing_rx) = mpsc::channel::<SendSpliceTask>(2);

        let mut join_set = JoinSet::<Result<(), ExecutionError>>::new();
        // Spawn the task to spawn the prove shard tasks.
        let (send_handle_tx, mut send_handle_rx) = mpsc::unbounded_channel();
        join_set.spawn(
            {
                let send_splice_engine = self.initialize_send_splice_engine(
                    elf_artifact.clone(),
                    common_input_artifact.clone(),
                    context.clone(),
                    prove_shard_tx.clone(),
                    deferred_marker_tx,
                );
                async move {
                    while let Some(task) = splicing_rx.recv().await {
                        let handle = send_splice_engine
                            .submit(task)
                            .instrument(tracing::debug_span!("send splice"))
                            .await
                            .map_err(|_| {
                                ExecutionError::Other(
                                    "failed to submit send splice task".to_string(),
                                )
                            })?;
                        send_handle_tx.send(handle).map_err(|e| {
                            ExecutionError::Other(format!("error sending to send handle tx: {}", e))
                        })?;
                    }
                    Ok(())
                }
            }
            .instrument(tracing::debug_span!("get splices to serialize")),
        );

        // This task waits for prove shard tasks to be sent.
        join_set.spawn(
            {
                async move {
                    let mut handles = FuturesUnordered::new();
                    loop {
                        tokio::select! {
                            Some(handle) = send_handle_rx.recv() => {
                                handles.push(handle);
                            }
                            Some(result) = handles.next() => {
                                result.map_err(|e| ExecutionError::Other(format!("failed to join send splice task: {}", e)))??;
                            }
                            else => {
                                break;
                            }
                        }
                    }
                    Ok::<_, ExecutionError>(())
                }
            }
            .instrument(tracing::debug_span!("spawn prove shard tasks")),
        );

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
            let mut touched_addresses = CompressedMemory::new();
            let mut vm = SplicingVM::new(&chunk, program.clone(), &mut touched_addresses, common_prover_input.nonce, opts);

            let start_num_mem_reads = chunk.num_mem_reads();
            let start_clk = vm.core.clk();
            let mut end_clk : u64;
            let mut last_splice = SplicedMinimalTrace::new_full_trace(chunk.clone());
                let mut boundary = ShardBoundary {
                    timestamp: start_clk,
                    initialized_address: 0,
                    finalized_address: 0,
                    initialized_page_index: 0,
                    finalized_page_index: 0,
                    deferred_proof: num_deferred_proofs as u64,
                };
            loop {
                tracing::debug!("starting new shard at clk: {} at pc: {}", vm.core.clk(), vm.core.pc());
                match vm.execute()? {
                    CycleResult::ShardBoundary => {
                        // Note: Chunk implentations should always be cheap to clone.
                        if let Some(spliced) = vm.splice(chunk.clone()) {
                            tracing::debug!(global_clk = vm.core.global_clk(), pc = vm.core.pc(), num_mem_reads_left = vm.core.mem_reads.len(), clk = vm.core.clk(), "shard boundary");
                            // Get the end boundary of the shard.
                            end_clk = vm.core.clk();
                            let end = ShardBoundary {
                                timestamp: end_clk,
                                initialized_address: 0,
                                finalized_address: 0,
                                initialized_page_index: 0,
                                finalized_page_index: 0,
                                deferred_proof: num_deferred_proofs as u64,
                            };
                            // Get the range of the shard.
                            let range = (boundary..end).into();
                            // Update the boundary to the end of the shard.
                            boundary = end;

                            // Set the last splice clk.
                            last_splice.set_last_clk(vm.core.clk());
                            last_splice.set_last_mem_reads_idx(
                                start_num_mem_reads as usize - vm.core.mem_reads.len(),
                            );
                            let splice_to_send = std::mem::replace(&mut last_splice, spliced);
                            tracing::debug!(global_clk = vm.core.global_clk(), "sending spliced trace to splicing tx");
                            splicing_tx.blocking_send(SendSpliceTask { chunk: splice_to_send, range })
                                .map_err(|e| ExecutionError::Other(format!("error sending to splicing tx: {}", e)))?;
                            tracing::debug!(global_clk = vm.core.global_clk(), "spliced trace sent to splicing tx");
                        } else {
                            tracing::debug!(global_clk = vm.core.global_clk(), pc = vm.core.pc(), num_mem_reads_left = vm.core.mem_reads.len(), "trace ended");
                            // Get the end boundary of the shard.
                            end_clk = vm.core.clk();
                            let end = ShardBoundary {
                                timestamp: end_clk,
                                initialized_address: 0,
                                finalized_address: 0,
                                initialized_page_index: 0,
                                finalized_page_index: 0,
                                deferred_proof: num_deferred_proofs as u64,
                            };
                            // Get the range of the shard.
                            let range = (boundary..end).into();

                            last_splice.set_last_clk(vm.core.clk());
                            last_splice.set_last_mem_reads_idx(
                                start_num_mem_reads as usize - vm.core.mem_reads.len(),
                            );
                            tracing::debug!(global_clk = vm.core.global_clk(), "sending last splice to splicing tx");
                            splicing_tx.blocking_send(SendSpliceTask { chunk: last_splice, range })
                                .map_err(|e| ExecutionError::Other(format!("error sending to splicing tx: {}", e)))?;
                            tracing::debug!(global_clk = vm.core.global_clk(), "last splice sent to splicing tx");
                            break;
                        }
                    }
                    CycleResult::Done(true) => {
                        tracing::debug!(global_clk = vm.core.global_clk(), "done cycle result");
                        last_splice.set_last_clk(vm.core.clk());
                        last_splice.set_last_mem_reads_idx(chunk.num_mem_reads() as usize);

                        // Get the end boundary of the shard.
                        end_clk = vm.core.clk();
                        let end = ShardBoundary {
                            timestamp: end_clk,
                            initialized_address: 0,
                            finalized_address: 0,
                            initialized_page_index: 0,
                            finalized_page_index: 0,
                            deferred_proof: num_deferred_proofs as u64,
                        };
                        // Get the range of the shard.
                        let range = (boundary..end).into();

                        // Get the last state of the vm execution and set the global final vm state to
                        // this value.
                        let final_state = FinalVmState::new(&vm.core);
                        final_vm_state.set(final_state).map_err(|e| ExecutionError::Other(e.to_string()))?;

                        tracing::debug!(global_clk = vm.core.global_clk(), "sending last splice to splicing tx");
                        // Send the last splice.
                        splicing_tx.blocking_send(SendSpliceTask { chunk: last_splice, range })
                            .map_err(|e| ExecutionError::Other(format!("error sending to splicing tx: {}", e)))?;
                        tracing::debug!(global_clk = vm.core.global_clk(), "last splice sent to splicing tx");
                        break;
                    }
                    CycleResult::Done(false) | CycleResult::TraceEnd => {
                        // Note: Trace ends get mapped to shard boundaries.
                        unreachable!("The executor should never return an imcomplete program without a shard boundary");
                    }
                }
            }
            // Append the touched addresses from this chunk to the globally tracked touched addresses.
            tracing::debug_span!("collecting touched addresses and sending to global memory").in_scope(|| {
            all_touched_addresses.blocking_extend(start_clk, end_clk, touched_addresses.is_set())
                .map_err(|e| ExecutionError::Other(e.to_string()))})?;
            Ok(())
           });

        // Wait for the tasks to finish and collect the errors.
        while let Some(result) = join_set.join_next().await {
            result
                .map_err(|e| ExecutionError::Other(format!("splicer task panicked: {}", e)))??;
        }

        Ok(())
    }
}

pub struct SendSpliceTask {
    pub chunk: SplicedMinimalTrace<TraceChunkRaw>,
    pub range: ShardRange,
}

struct SendSpliceWorker<A, W> {
    artifact_client: A,
    worker_client: W,
    context: TaskContext,
    elf_artifact: Artifact,
    common_input_artifact: Artifact,
    prove_shard_tx: mpsc::UnboundedSender<ProofData>,
    deferred_marker_tx: mpsc::UnboundedSender<DeferredMessage>,
}

impl<A, W> AsyncWorker<SendSpliceTask, Result<(), ExecutionError>> for SendSpliceWorker<A, W>
where
    A: ArtifactClient,
    W: WorkerClient,
{
    async fn call(&self, input: SendSpliceTask) -> Result<(), ExecutionError> {
        let SendSpliceTask { chunk, range } = input;
        let chunk_bytes = await_blocking(|| bincode::serialize(&chunk))
            .await
            .map_err(|_| ExecutionError::Other("chunk serialization failed".to_string()))?
            .map_err(|e| ExecutionError::Other(e.to_string()))?;
        let data = TraceData::Core(chunk_bytes);

        let SpawnProveOutput { deferred_message, proof_data } = create_core_proving_task(
            self.elf_artifact.clone(),
            self.common_input_artifact.clone(),
            self.context.clone(),
            range,
            data,
            self.worker_client.clone(),
            self.artifact_client.clone(),
        )
        .await
        .map_err(|e| ExecutionError::Other(format!("error in create_core_proving_task: {}", e)))?;

        self.prove_shard_tx
            .send(proof_data)
            .map_err(|e| ExecutionError::Other(format!("error in send proof data: {}", e)))?;
        // Send the deferred message to the deferred marker receiver.
        if let Some(deferred_message) = deferred_message {
            self.deferred_marker_tx.send(deferred_message).map_err(|e| {
                ExecutionError::Other(format!("error in send deferred message: {}", e))
            })?;
        }
        Ok(())
    }
}

type SendSpliceEngine<A, W> =
    AsyncEngine<SendSpliceTask, Result<(), ExecutionError>, SendSpliceWorker<A, W>>;
