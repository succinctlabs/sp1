use std::{
    marker::PhantomData,
    sync::{Arc, OnceLock},
};

use serde::{Deserialize, Serialize};
use sp1_core_executor::{
    events::MemoryRecord, CoreVM, ExecutionError, Program, SP1CoreOpts, UnsafeMemory,
};
use sp1_core_executor_runner::MinimalExecutorRunner;
use sp1_core_machine::{executor::ExecutionOutput, io::SP1Stdin, riscv::RiscvAir};
use sp1_hypercube::{
    air::{ShardRange, PROOF_NONCE_NUM_WORDS, PV_DIGEST_NUM_WORDS},
    Machine, SP1PcsProofInner, SP1VerifyingKey, ShardProof, DIGEST_SIZE,
};
use sp1_jit::MinimalTrace;
use sp1_primitives::{SP1Field, SP1GlobalContext};
use sp1_prover_types::{
    network_base_types::ProofMode, Artifact, ArtifactClient, SerializableRiscvMachine,
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};

use crate::worker::{
    controller::{
        pin_cores_enabled, pin_current_thread_to_cpu, pinned_pool_cpus, ChunkPayload, LeafState,
        TaskInput,
    },
    node_body::SpliceChunkTask,
    MinimalExecutorCache, RawTaskRequest, TaskContext, TaskError, TaskId, WorkerClient,
};

/// Whether the shard proves the merkle update or a part of execution.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ProofKind {
    Execution,
    Merkle,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum ProofData {
    /// Cluster-path proof (deferred recursion proofs from `SP1Stdin.proofs`).
    Artifact { task_id: TaskId, range: ShardRange, proof: Artifact },
    /// In-process proof produced by the node body.
    InMemory {
        kind: ProofKind,
        range: ShardRange,
        proof: Box<ShardProof<SP1GlobalContext, SP1PcsProofInner>>,
    },
}

#[derive(Debug, Clone)]
pub struct MessageSender<W: WorkerClient, T: Serialize> {
    worker_client: W,
    task_id: TaskId,
    _marker: PhantomData<T>,
}

impl<W: WorkerClient, T: Serialize> MessageSender<W, T> {
    pub fn new(worker_client: W, task_id: TaskId) -> Self {
        Self { worker_client, task_id, _marker: PhantomData }
    }

    pub async fn send(&self, message: T) -> anyhow::Result<()> {
        let payload = bincode::serialize(&message)?;
        self.worker_client.send_task_message(&self.task_id, payload).await
    }
}

#[derive(Serialize, Deserialize)]
struct CoreExecuteMetadata {
    num_deferred_proofs: usize,
    cycle_limit: Option<u64>,
    machine: SerializableRiscvMachine,
    #[serde(default)]
    stdin_private: bool,
}

pub struct CoreExecuteTaskRequest {
    pub elf: Artifact,
    pub stdin: Artifact,
    pub common_input: Artifact,
    pub execution_output: Artifact,
    pub num_deferred_proofs: usize,
    pub cycle_limit: Option<u64>,
    pub context: TaskContext,
    pub machine: Machine<SP1Field, RiscvAir<SP1Field>>,
    pub stdin_private: bool,
}

impl CoreExecuteTaskRequest {
    pub fn from_raw(request: RawTaskRequest) -> Result<Self, TaskError> {
        let RawTaskRequest { inputs, outputs, context } = request;
        let [elf, stdin, common_input, metadata] = inputs
            .try_into()
            .map_err(|e| TaskError::Fatal(anyhow::anyhow!("invalid task inputs: {e:?}")))?;
        let [execution_output] = outputs
            .try_into()
            .map_err(|e| TaskError::Fatal(anyhow::anyhow!("invalid task outputs: {e:?}")))?;
        let CoreExecuteMetadata { num_deferred_proofs, cycle_limit, machine, stdin_private } =
            serde_json::from_str(&metadata.to_id()).map_err(|e| {
                TaskError::Fatal(anyhow::anyhow!("failed to deserialize CoreExecuteMetadata: {e}"))
            })?;
        Ok(CoreExecuteTaskRequest {
            elf,
            stdin,
            common_input,
            execution_output,
            num_deferred_proofs,
            cycle_limit,
            context,
            machine: machine.into(),
            stdin_private,
        })
    }

    pub fn into_raw(self) -> Result<RawTaskRequest, TaskError> {
        let metadata = CoreExecuteMetadata {
            num_deferred_proofs: self.num_deferred_proofs,
            cycle_limit: self.cycle_limit,
            machine: self.machine.into(),
            stdin_private: self.stdin_private,
        };
        let metadata_str = serde_json::to_string(&metadata).map_err(|e| {
            TaskError::Fatal(anyhow::anyhow!("failed to serialize CoreExecuteMetadata: {e}"))
        })?;
        let metadata_artifact = Artifact::from(metadata_str);

        let inputs = vec![self.elf, self.stdin, self.common_input, metadata_artifact];
        let outputs = vec![self.execution_output];
        Ok(RawTaskRequest { inputs, outputs, context: self.context })
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CommonProverInput {
    pub vk: SP1VerifyingKey,
    pub mode: ProofMode,
    pub deferred_digest: [u32; DIGEST_SIZE],
    pub num_deferred_proofs: usize,
    pub nonce: [u32; PROOF_NONCE_NUM_WORDS],
}

pub struct SP1CoreExecutor<A: ArtifactClient, W: WorkerClient> {
    chunk_tx: mpsc::Sender<SpliceChunkTask<W>>,
    elf: Artifact,
    stdin: Arc<SP1Stdin>,
    common_input: Artifact,
    opts: SP1CoreOpts,
    num_deferred_proofs: usize,
    sender: MessageSender<W, ProofData>,
    artifact_client: A,
    minimal_executor_cache: Option<MinimalExecutorCache>,
    cycle_limit: Option<u64>,
    _machine: Machine<SP1Field, RiscvAir<SP1Field>>,
}

impl<A: ArtifactClient, W: WorkerClient> SP1CoreExecutor<A, W> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chunk_tx: mpsc::Sender<SpliceChunkTask<W>>,
        elf: Artifact,
        stdin: Arc<SP1Stdin>,
        common_input: Artifact,
        opts: SP1CoreOpts,
        num_deferred_proofs: usize,
        sender: MessageSender<W, ProofData>,
        artifact_client: A,
        minimal_executor_cache: Option<MinimalExecutorCache>,
        cycle_limit: Option<u64>,
        _machine: Machine<SP1Field, RiscvAir<SP1Field>>,
    ) -> Self {
        Self {
            chunk_tx,
            elf,
            stdin,
            common_input,
            opts,
            num_deferred_proofs,
            sender,
            artifact_client,
            minimal_executor_cache,
            cycle_limit,
            _machine,
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

        let chunk_tx = self.chunk_tx;

        let mut join_set = JoinSet::<Result<(), TaskError>>::new();

        let (memory_tx, memory_rx) = oneshot::channel::<UnsafeMemory>();
        let (minimal_executor_tx, _minimal_executor_rx) =
            oneshot::channel::<MinimalExecutorRunner>();
        let (output_tx, output_rx) = oneshot::channel::<ExecutionOutput>();
        let span = tracing::debug_span!("minimal executor");

        let dirty_pages_slot_bytes: usize = 256 * 1024 * 1024;

        let mut minimal_executor = if let Some(cache) = &self.minimal_executor_cache {
            let mut optional_minimal_executor = cache.lock().await;
            if let Some(minimal_executor) = optional_minimal_executor.take() {
                tracing::info!("minimal executor cache hit");
                minimal_executor
            } else {
                MinimalExecutorRunner::new_with_dirty_pages(
                    program.clone(),
                    false,
                    Some(opts.minimal_trace_chunk_threshold),
                    opts.memory_limit,
                    opts.trace_chunk_slots,
                    Some(dirty_pages_slot_bytes),
                )
            }
        } else {
            MinimalExecutorRunner::new_with_dirty_pages(
                program.clone(),
                false,
                Some(opts.minimal_trace_chunk_threshold),
                opts.memory_limit,
                opts.trace_chunk_slots,
                Some(dirty_pages_slot_bytes),
            )
        };

        // Optional pinning (LEAVES_PIN_CORES=1 in env):
        //   CPU 0 -> JIT child (via SP1_RUNNER_PIN_CORE=0)
        //   CPU 1 -> recv thread
        //   CPUs 2..N_physical -> dedicated rayon pool for LeafState hashing
        let pin_cores = pin_cores_enabled();
        let hw_logical = num_cpus::get();
        let hw_physical = num_cpus::get_physical();
        if pin_cores {
            std::env::set_var("SP1_RUNNER_PIN_CORE", "0");
        }

        join_set.spawn_blocking({
            let program = program.clone();
            let common_input_artifact = self.common_input.clone();
            let sender = self.sender.clone();
            let opts = opts.clone();
            let chunk_tx = chunk_tx.clone();
            let cycle_limit = self.cycle_limit;
            let num_deferred_proofs = self.num_deferred_proofs;

            move || {
                let _guard = span.enter();
                for buf in stdin.buffer.iter() {
                    minimal_executor.with_input(buf);
                }
                let unsafe_memory = minimal_executor.unsafe_memory();
                memory_tx
                    .send(unsafe_memory)
                    .map_err(|_| anyhow::anyhow!("failed to send unsafe memory"))?;

                if pin_cores {
                    pin_current_thread_to_cpu(1);
                }

                // Set up the hash-worker channel.
                let (hash_tx, hash_rx) = std::sync::mpsc::sync_channel::<
                    (sp1_jit::TraceChunkRaw, sp1_jit::DirtyPages),
                >(4);

                // Spawn the hash worker.
                let hash_handle = std::thread::Builder::new()
                    .name("controller-leaf-hash".into())
                    .spawn({
                        let program = program.clone();
                        let common_input_artifact = common_input_artifact.clone();
                        let sender = sender.clone();
                        let opts = opts.clone();
                        let chunk_tx = chunk_tx.clone();
                        move || -> Result<(), TaskError> {
                            let pinned_pool = if pin_cores {
                                crate::worker::controller::build_pinned_rayon_pool(
                                    pinned_pool_cpus(hw_physical, hw_logical),
                                )
                            } else {
                                None
                            };
                            tracing::debug!(
                                pin_cores,
                                ?hw_physical,
                                ?hw_logical,
                                pool_threads = pinned_pool.as_ref().map(|p| p.current_num_threads()),
                                "leaf-hash worker starting"
                            );

                            let mut leaf_state =
                                LeafState::from_memory_image(&program.memory_image);
                            let mut chunk_idx: u64 = 0;
                            while let Ok((chunk, dirty_pages)) = hash_rx.recv() {
                                let pre_chunk_snapshot = leaf_state.snapshot();
                                let leaf_start = std::time::Instant::now();
                                let (prev_leaves, new_leaves) =
                                    if let Some(pool) = pinned_pool.as_ref() {
                                        pool.install(|| {
                                            leaf_state.ingest_chunk(&dirty_pages.pages)
                                        })
                                    } else {
                                        leaf_state.ingest_chunk(&dirty_pages.pages)
                                    };
                                let leaf_elapsed = leaf_start.elapsed();
                                tracing::debug!(
                                    chunk_idx,
                                    dirty_pages = dirty_pages.pages.len(),
                                    leaf_ingest_ms = leaf_elapsed.as_secs_f64() * 1000.0,
                                    cumulative_touched_pages = leaf_state.touched_pages(),
                                    "leaf-hash worker ingested chunk"
                                );
                                let payload = ChunkPayload {
                                    chunk_idx,
                                    chunk: chunk.clone(),
                                    dirty_page_ids: dirty_pages
                                        .pages
                                        .iter()
                                        .map(|p| p.page_id)
                                        .collect(),
                                    prev_leaves,
                                    new_leaves,
                                    dirty_page_final_contents: dirty_pages
                                        .pages
                                        .into_iter()
                                        .map(|p| p.final_contents)
                                        .collect(),
                                    pre_chunk_snapshot,
                                };
                                let task = SpliceChunkTask {
                                    payload: TaskInput::local(payload),
                                    program: program.clone(),
                                    num_deferred_proofs,
                                    common_input_artifact: common_input_artifact.clone(),
                                    prove_shard_tx: sender.clone(),
                                    opts: opts.clone(),
                                };
                                chunk_tx.blocking_send(task).map_err(|e| {
                                    TaskError::Fatal(anyhow::anyhow!(
                                        "failed to hand off SpliceChunk task: {e}"
                                    ))
                                })?;
                                chunk_idx += 1;
                            }
                            tracing::debug!(
                                total_chunks = chunk_idx,
                                "leaf-hash worker draining; recv channel closed"
                            );
                            Ok(())
                        }
                    })
                    .map_err(|e| anyhow::anyhow!("spawn leaf-hash worker: {e}"))?;

                tracing::debug!("Starting minimal executor");
                let now = std::time::Instant::now();
                let mut chunk_count = 0;

                while let Some((chunk, dirty_pages)) = minimal_executor
                    .try_execute_chunk_with_dirty_pages()
                    .map_err(|e| anyhow::anyhow!("failed to execute chunk: {e}"))?
                {
                    if let Some(cycle_limit) = cycle_limit {
                        let last_clk = chunk.global_clk_end();
                        if last_clk > cycle_limit {
                            tracing::error!(
                                "Cycle limit exceeded: last_clk = {last_clk}, cycle_limit = {cycle_limit}"
                            );
                            return Err(TaskError::Execution(ExecutionError::ExceededCycleLimit(
                                cycle_limit,
                            )));
                        }
                    }

                    tracing::debug!(
                        trace_chunk = chunk_count,
                        dirty_pages = dirty_pages.pages.len(),
                        "mem reads chunk size bytes {}, program is done?: {}",
                        chunk.num_mem_reads() * std::mem::size_of::<sp1_jit::MemValue>() as u64,
                        minimal_executor.is_done()
                    );

                    hash_tx.send((chunk, dirty_pages)).map_err(|e| {
                        anyhow::anyhow!("failed to send to leaf-hash worker: {e}")
                    })?;
                    chunk_count += 1;
                }
                // Signal the hash worker that no more chunks are coming.
                drop(hash_tx);

                hash_handle
                    .join()
                    .map_err(|e| anyhow::anyhow!("leaf-hash worker panicked: {e:?}"))??;

                let elapsed = now.elapsed().as_secs_f64();
                tracing::debug!(
                    "minimal Executor finished. elapsed: {}s, mhz: {}",
                    elapsed,
                    minimal_executor.global_clk() as f64 / (elapsed * 1e6)
                );

                if chunk_count == 0 {
                    return Err(TaskError::Fatal(anyhow::anyhow!(
                        "executor produced zero trace chunks in {elapsed:.3}s \
                         (global_clk={}, is_done={})",
                        minimal_executor.global_clk(),
                        minimal_executor.is_done(),
                    )));
                }
                let cycles = minimal_executor.global_clk();
                let public_value_stream = minimal_executor.public_values_stream().clone();

                let output = ExecutionOutput { cycles, public_value_stream };
                output_tx.send(output).map_err(|_| anyhow::anyhow!("failed to send output"))?;
                minimal_executor_tx
                    .send(minimal_executor)
                    .map_err(|_| anyhow::anyhow!("failed to send minimal executor"))?;
                Ok::<_, TaskError>(())
            }
        });

        // Drop the executor's `chunk_tx` clone now that the JIT thread
        // (which holds its own clone) is spawned. Without this drop,
        // the receiver would never see the end of the stream.
        drop(chunk_tx);

        let _memory =
            memory_rx.await.map_err(|_| anyhow::anyhow!("failed to receive unsafe memory"))?;

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
    pub fn new<'a, 'b, M: sp1_core_executor::ExecutionMode>(vm: &'a CoreVM<'b, M>) -> Self {
        let registers = *vm.registers();
        let timestamp = vm.clk();
        let pc = vm.pc();
        let exit_code = vm.exit_code();
        let public_value_digest = vm.public_value_digest;
        let proof_nonce = vm.proof_nonce;

        Self { registers, timestamp, pc, exit_code, public_value_digest, proof_nonce }
    }

    /// Create from a `GasEstimatingVMEnum`.
    pub fn from_gas_estimating_vm_enum(vm: &sp1_core_executor::GasEstimatingVMEnum<'_>) -> Self {
        Self {
            registers: vm.registers(),
            timestamp: vm.clk(),
            pc: vm.pc(),
            exit_code: vm.exit_code(),
            public_value_digest: vm.public_value_digest(),
            proof_nonce: vm.proof_nonce(),
        }
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
