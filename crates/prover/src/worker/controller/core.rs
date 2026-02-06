use std::sync::{Arc, OnceLock};

use futures::{prelude::*, stream::FuturesUnordered};
use serde::{Deserialize, Serialize};
use slop_futures::pipeline::Pipeline;
use sp1_core_executor::{
    events::{MemoryInitializeFinalizeEvent, MemoryRecord},
    CoreVM, ExecutionError, MinimalExecutor, Program, SP1CoreOpts, SyscallCode, UnsafeMemory,
};
use sp1_core_machine::{executor::ExecutionOutput, io::SP1Stdin};
use sp1_hypercube::{
    air::{ShardRange, PROOF_NONCE_NUM_WORDS, PV_DIGEST_NUM_WORDS},
    SP1VerifyingKey, DIGEST_SIZE,
};
use sp1_jit::MinimalTrace;
use sp1_prover_types::{network_base_types::ProofMode, Artifact, ArtifactClient, TaskType};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};
use tracing::Instrument;

use crate::worker::{
    global_memory, precompile_channel, DeferredMessage, MinimalExecutorCache,
    PrecompileArtifactSlice, ProveShardTaskRequest, RawTaskRequest, SplicingEngine, SplicingTask,
    TaskContext, TaskError, TaskId, WorkerClient,
};

#[derive(Debug)]
pub struct ProofData {
    pub task_id: TaskId,
    pub range: ShardRange,
    pub proof: Artifact,
}

#[derive(Serialize, Deserialize)]
pub enum TraceData {
    /// A core record to be proven.
    Core(Vec<u8>),
    // Precompile data. Several `PrecompileArtifactSlice`s, and the type of precompile.
    Precompile(Vec<PrecompileArtifactSlice>, SyscallCode),
    /// Memory data.
    Memory(Box<GlobalMemoryShard>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalMemoryShard {
    pub final_state: FinalVmState,
    pub initialize_events: Vec<MemoryInitializeFinalizeEvent>,
    pub finalize_events: Vec<MemoryInitializeFinalizeEvent>,
    pub previous_init_addr: u64,
    pub previous_finalize_addr: u64,
    pub previous_init_page_idx: u64,
    pub previous_finalize_page_idx: u64,
    pub last_init_addr: u64,
    pub last_finalize_addr: u64,
    pub last_init_page_idx: u64,
    pub last_finalize_page_idx: u64,
}

pub struct ProveShardInput {
    pub elf: Vec<u8>,
    pub common_input: CommonProverInput,
    pub record: TraceData,
    pub opts: SP1CoreOpts,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CommonProverInput {
    pub vk: SP1VerifyingKey,
    pub mode: ProofMode,
    pub deferred_digest: [u32; DIGEST_SIZE],
    pub num_deferred_proofs: usize,
    pub nonce: [u32; PROOF_NONCE_NUM_WORDS],
}

pub struct SP1CoreExecutor<A, W> {
    splicing_engine: Arc<SplicingEngine<A, W>>,
    global_memory_buffer_size: usize,
    elf: Artifact,
    stdin: Arc<SP1Stdin>,
    common_input: Artifact,
    opts: SP1CoreOpts,
    num_deferred_proofs: usize,
    context: TaskContext,
    sender: mpsc::UnboundedSender<ProofData>,
    artifact_client: A,
    worker_client: W,
    minimal_executor_cache: Option<MinimalExecutorCache>,
    cycle_limit: Option<u64>,
}

impl<A, W> SP1CoreExecutor<A, W> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        splicing_engine: Arc<SplicingEngine<A, W>>,
        global_memory_buffer_size: usize,
        elf: Artifact,
        stdin: Arc<SP1Stdin>,
        common_input: Artifact,
        opts: SP1CoreOpts,
        num_deferred_proofs: usize,
        context: TaskContext,
        sender: mpsc::UnboundedSender<ProofData>,
        artifact_client: A,
        worker_client: W,
        minimal_executor_cache: Option<MinimalExecutorCache>,
        cycle_limit: Option<u64>,
    ) -> Self {
        Self {
            splicing_engine,
            global_memory_buffer_size,
            elf,
            stdin,
            common_input,
            opts,
            num_deferred_proofs,
            context,
            sender,
            artifact_client,
            worker_client,
            minimal_executor_cache,
            cycle_limit,
        }
    }
}

impl<A, W> SP1CoreExecutor<A, W>
where
    A: ArtifactClient,
    W: WorkerClient,
{
    pub async fn execute(self) -> Result<ExecutionOutput, TaskError> {
        let elf_bytes = self.artifact_client.download_program(&self.elf).await?;
        let stdin = self.stdin.clone();
        let opts = self.opts.clone();

        // Get the program from the elf. TODO: handle errors.
        let program = Arc::new(Program::from(&elf_bytes).map_err(|e| {
            TaskError::Execution(ExecutionError::Other(format!(
                "failed to dissassemble program: {}",
                e
            )))
        })?);

        // Initialize the touched addresses map.
        let (all_touched_addresses, global_memory_handler) =
            global_memory(self.global_memory_buffer_size);
        let (deferred_marker_tx, precompile_handler) = precompile_channel(&program, &opts);
        // Initialize the final vm state.
        let final_vm_state = FinalVmStateLock::new();
        let (final_state_tx, final_state_rx) = oneshot::channel::<FinalVmState>();

        // Create a join set in order to be able to cancel all tasks
        let mut join_set = JoinSet::<Result<(), TaskError>>::new();

        // Start the minimal executor.
        let (memory_tx, memory_rx) = oneshot::channel::<UnsafeMemory>();
        let (minimal_executor_tx, minimal_executor_rx) = oneshot::channel::<MinimalExecutor>();
        let (output_tx, output_rx) = oneshot::channel::<ExecutionOutput>();
        // Create a channel to send the splicing handles to be awaited and their task_ids being
        // sent after being submitted to the splicing pipeline.
        let (splicing_submit_tx, mut splicing_submit_rx) = mpsc::unbounded_channel();
        let span = tracing::debug_span!("minimal executor");

        // Making the minimal executor blocks the rest of execution anyway, so we initialize it before spawning the rest of the tokio tasks.
        let mut minimal_executor = if let Some(cache) = &self.minimal_executor_cache {
            let mut optional_minimal_executor = cache.lock().await;
            if let Some(minimal_executor) = optional_minimal_executor.take() {
                tracing::info!("minimal executor cache hit");
                minimal_executor
            } else {
                MinimalExecutor::tracing(program.clone(), opts.minimal_trace_chunk_threshold)
            }
        } else {
            MinimalExecutor::tracing(program.clone(), opts.minimal_trace_chunk_threshold)
        };
        join_set.spawn_blocking({
            let program = program.clone();
            let elf = self.elf.clone();
            let common_input_artifact = self.common_input.clone();
            let context = self.context.clone();
            let sender = self.sender.clone();
            let final_vm_state = final_vm_state.clone();
            let opts = opts.clone();
            let splicing_engine = self.splicing_engine.clone();

            move || {
                let _guard = span.enter();
                // Write input to the minimal executor.
                for buf in stdin.buffer.iter() {
                    minimal_executor.with_input(buf);
                }
                // Get the unsafe memory view of the minimal executor.
                let unsafe_memory = minimal_executor.unsafe_memory();
                // Send the unsafe memory view to the parent task.
                memory_tx
                    .send(unsafe_memory)
                    .map_err(|_| anyhow::anyhow!("failed to send unsafe memory"))?;
                tracing::debug!("Starting minimal executor");
                let now = std::time::Instant::now();
                let mut chunk_count = 0;
                while let Some(chunk) = minimal_executor.execute_chunk() {
                    tracing::debug!(
                        trace_chunk = chunk_count,
                        "mem reads chunk size bytes {}, program is done?: {}",
                        chunk.num_mem_reads() * std::mem::size_of::<sp1_jit::MemValue>() as u64,
                        minimal_executor.is_done()
                    );

                    // Check the `end_clk` for cycle limit
                    if let Some(cycle_limit) = self.cycle_limit {
                        let last_clk = minimal_executor.global_clk();
                        if last_clk > cycle_limit {
                            tracing::error!(
                                "Cycle limit exceeded: last_clk = {}, cycle_limit = {}",
                                last_clk,
                                cycle_limit
                            );
                            return Err(TaskError::Execution(ExecutionError::ExceededCycleLimit(
                                cycle_limit,
                            )));
                        }
                    }

                    // Create a splicing task
                    let task = SplicingTask {
                        program: program.clone(),
                        chunk,
                        elf_artifact: elf.clone(),
                        common_input_artifact: common_input_artifact.clone(),
                        num_deferred_proofs: self.num_deferred_proofs,
                        all_touched_addresses: all_touched_addresses.clone(),
                        final_vm_state: final_vm_state.clone(),
                        prove_shard_tx: sender.clone(),
                        context: context.clone(),
                        opts: opts.clone(),
                        deferred_marker_tx: deferred_marker_tx.clone(),
                    };

                    let splicing_handle = tracing::debug_span!("splicing", idx = chunk_count)
                        .in_scope(|| {
                            splicing_engine.blocking_submit(task).map_err(|e| {
                                anyhow::anyhow!("failed to submit splicing task: {}", e)
                            })
                        })?;
                    splicing_submit_tx
                        .send((chunk_count, splicing_handle))
                        .map_err(|e| anyhow::anyhow!("failed to send splicing handle: {}", e))?;

                    chunk_count += 1;
                }
                let elapsed = now.elapsed().as_secs_f64();
                tracing::debug!(
                    "minimal Executor finished. elapsed: {}s, mhz: {}",
                    elapsed,
                    minimal_executor.global_clk() as f64 / (elapsed * 1e6)
                );
                // Get the output and send it to the output channel.
                let cycles = minimal_executor.global_clk();
                let public_value_stream = minimal_executor.public_values_stream().clone();

                let output = ExecutionOutput { cycles, public_value_stream };
                output_tx.send(output).map_err(|_| anyhow::anyhow!("failed to send output"))?;
                // Send the hints to the global memory handler.
                minimal_executor_tx
                    .send(minimal_executor)
                    .map_err(|_| anyhow::anyhow!("failed to send minimal executor"))?;
                Ok::<_, TaskError>(())
            }
        });

        let memory =
            memory_rx.await.map_err(|_| anyhow::anyhow!("failed to receive unsafe memory"))?;

        join_set.spawn({
            async move {
                let mut splicing_handles = FuturesUnordered::new();
                loop {
                    tokio::select! {
                        Some((chunk_count, splicing_handle)) = splicing_submit_rx.recv() => {
                            tracing::debug!(chunk_count = chunk_count, "Received splicing handle");
                            let handle = splicing_handle.map_ok(move |_| chunk_count);
                            splicing_handles.push(handle);
                        }
                        Some(result) = splicing_handles.next() => {
                            let chunk_count = result.map_err(|e| anyhow::anyhow!("splicing task panicked: {}", e))?;
                            tracing::debug!(chunk_count = chunk_count, "Splicing task finished");
                        }
                        else => {
                            tracing::debug!("No more splicing handles to receive");
                            break;
                        }
                    }
                }
                // Now that all the splicing tasks are finished, send the final vm state to the global memory handler.
                let final_state = *final_vm_state.get().ok_or(TaskError::Fatal(anyhow::anyhow!("final vm state not set")))?;
                final_state_tx.send(final_state).map_err(|_| anyhow::anyhow!("failed to send final vm state"))?;
                Ok::<_, TaskError>(())
            }
            .instrument(tracing::debug_span!("wait for splicers"))
        });

        // Emit the global memory shards.
        join_set.spawn(
            {
                let artifact_client = self.artifact_client.clone();
                let worker_client = self.worker_client.clone();
                let num_deferred_proofs = self.num_deferred_proofs;
                let sender = self.sender.clone();
                let elf = self.elf.clone();
                let common_input = self.common_input.clone();
                let context = self.context.clone();
                let minimal_executor_cache = self.minimal_executor_cache.clone();

                async move {
                    global_memory_handler
                        .emit_global_memory_shards(
                            program,
                            final_state_rx,
                            minimal_executor_rx,
                            sender,
                            elf,
                            common_input,
                            context,
                            memory,
                            opts,
                            num_deferred_proofs,
                            artifact_client,
                            worker_client,
                            minimal_executor_cache,
                        )
                        .await?;
                    Ok::<_, TaskError>(())
                }
            }
            .instrument(tracing::debug_span!("emit global memory shards")),
        );

        // Emit the precompile shards.
        join_set.spawn({
            let artifact_client = self.artifact_client.clone();
            let worker_client = self.worker_client.clone();
            let sender = self.sender.clone();
            let elf = self.elf.clone();
            let common_input = self.common_input.clone();
            let context = self.context.clone();
            async move {
                precompile_handler
                    .emit_precompile_shards(
                        elf,
                        common_input,
                        sender,
                        artifact_client,
                        worker_client,
                        context,
                    )
                    .await?;
                Ok::<_, TaskError>(())
            }
            .instrument(tracing::debug_span!("emit precompile shards"))
        });

        // Wait for tasks to finish
        while let Some(result) = join_set.join_next().await {
            result.map_err(|e| TaskError::Fatal(e.into()))??;
        }

        let output = output_rx.await.map_err(|_| anyhow::anyhow!("failed to receive output"))?;

        Ok(output)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct FinalVmState {
    pub registers: [MemoryRecord; 32],
    pub timestamp: u64,
    pub pc: u64,
    pub exit_code: u32,
    pub public_value_digest: [u32; PV_DIGEST_NUM_WORDS],
    pub proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
}

impl FinalVmState {
    pub fn new<'a, 'b>(vm: &'a CoreVM<'b>) -> Self {
        let registers = *vm.registers();
        let timestamp = vm.clk();
        let pc = vm.pc();
        let exit_code = vm.exit_code();
        let public_value_digest = vm.public_value_digest;
        let proof_nonce = vm.proof_nonce;

        Self { registers, timestamp, pc, exit_code, public_value_digest, proof_nonce }
    }
}

#[derive(Debug, Clone)]
pub struct FinalVmStateLock {
    inner: Arc<OnceLock<FinalVmState>>,
}

impl Default for FinalVmStateLock {
    fn default() -> Self {
        Self::new()
    }
}

impl FinalVmStateLock {
    pub fn new() -> Self {
        Self { inner: Arc::new(OnceLock::new()) }
    }

    pub fn set(&self, state: FinalVmState) -> Result<(), TaskError> {
        self.inner
            .set(state)
            .map_err(|_| TaskError::Fatal(anyhow::anyhow!("final vm state already set")))
    }

    pub fn get(&self) -> Option<&FinalVmState> {
        self.inner.get()
    }
}

pub struct SpawnProveOutput {
    pub deferred_message: Option<DeferredMessage>,
    pub proof_data: ProofData,
}

pub(super) async fn create_core_proving_task<A: ArtifactClient, W: WorkerClient>(
    elf_artifact: Artifact,
    common_input_artifact: Artifact,
    context: TaskContext,
    range: ShardRange,
    trace_data: TraceData,
    worker_client: W,
    artifact_client: A,
) -> Result<SpawnProveOutput, ExecutionError> {
    let record_artifact =
        artifact_client.create_artifact().map_err(|e| ExecutionError::Other(e.to_string()))?;

    // Make a deferred marker task. This is used for the worker to send
    // its deferred record back to the controller.
    let deferred_message = match &trace_data {
        TraceData::Core(_) => {
            let marker_task_id = worker_client
                .submit_task(
                    TaskType::MarkerDeferredRecord,
                    RawTaskRequest {
                        inputs: vec![],
                        outputs: vec![],
                        context: TaskContext {
                            proof_id: context.proof_id.clone(),
                            parent_id: None,
                            parent_context: None,
                            requester_id: context.requester_id.clone(),
                        },
                    },
                )
                .await
                .map_err(|e| ExecutionError::Other(e.to_string()))?;
            let deferred_output_artifact = artifact_client
                .create_artifact()
                .map_err(|e| ExecutionError::Other(e.to_string()))?;
            Some(DeferredMessage { task_id: marker_task_id, record: deferred_output_artifact })
        }
        TraceData::Memory(_) | TraceData::Precompile(_, _) => None,
    };

    artifact_client
        .upload(&record_artifact, trace_data)
        .await
        .map_err(|e| ExecutionError::Other(e.to_string()))?;

    // Allocate an artifact for the proof
    let proof_artifact = artifact_client
        .create_artifact()
        .map_err(|_| ExecutionError::Other("failed to create shard proof artifact".to_string()))?;

    let request = ProveShardTaskRequest {
        elf: elf_artifact,
        common_input: common_input_artifact,
        record: record_artifact,
        output: proof_artifact.clone(),
        deferred_marker_task: deferred_message
            .as_ref()
            .map(|m| Artifact::from(m.task_id.to_string()))
            .unwrap_or(Artifact::from("dummy marker task".to_string())),
        deferred_output: deferred_message
            .as_ref()
            .map(|m| m.record.clone())
            .unwrap_or(Artifact::from("dummy output artifact".to_string())),
        context,
    };

    let task = request.into_raw().map_err(|e| ExecutionError::Other(e.to_string()))?;

    // Send the task to the worker.
    let task_id = worker_client
        .submit_task(TaskType::ProveShard, task)
        .await
        .map_err(|e| ExecutionError::Other(e.to_string()))?;
    let proof_data = ProofData { task_id, range, proof: proof_artifact };
    Ok(SpawnProveOutput { deferred_message, proof_data })
}
