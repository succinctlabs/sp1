use crate::{
    build::{try_build_groth16_artifacts_dir, try_build_plonk_artifacts_dir},
    recursion::{
        chunk_compose_program_from_input, deferred_program_from_input, dummy_deferred_input,
        global_compose_program_from_input, recursive_verifier, shrink_program_from_input,
        wrap_program_from_input, RecursionVks,
    },
    shapes::{SP1NormalizeCache, SP1RecursionProofShape, DEFAULT_ARITY},
    verify::WRAP_VK_BYTES,
    worker::{
        ChunkChallengeCtx, CommonProverInput, DeferredInputs, NormalizeProgramCompiler,
        ProverMetrics, RangeProofs, RawTaskRequest, RecursionStages, TaskContext, TaskError,
        TaskMetadata, WrapAirProverInit,
    },
    ComposeScope, RecursionSC, SP1CircuitWitness, SP1ProverComponents,
};
use core::sync::atomic::AtomicBool;
use futures::future::BoxFuture;
use slop_algebra::PrimeField32;
use slop_algebra::{AbstractField, PrimeField};
use slop_bn254::Bn254Fr;
use slop_challenger::IopCtx;
use slop_futures::pipeline::{
    AsyncEngine, AsyncWorker, BlockingEngine, BlockingWorker, Chain, Pipeline, SubmitError,
    SubmitHandle,
};
use slop_symmetric::{CryptographicHasher, Permutation};
use sp1_core_machine::riscv::RiscvAir;
use sp1_hypercube::{
    inner_perm, koalabears_to_bn254,
    prover::{AirProver, ProverSemaphore, ProvingKey},
    HashableKey, Machine, MachineProof, MachineVerifier, MachineVerifyingKey, MerkleProof,
    SP1PcsProofInner, SP1PcsProofOuter, SP1RecursionProof, SP1WrapProof, ShardProof, DIGEST_SIZE,
};
use sp1_primitives::{SP1ExtensionField, SP1Field, SP1GlobalContext, SP1OuterGlobalContext};
use sp1_prover_types::{Artifact, ArtifactClient, ArtifactId};
use sp1_recursion_circuit::{
    machine::{
        SP1CompressWithVKeyWitnessValues, SP1MerkleProofWitnessValues, SP1NormalizeWitnessValues,
        SP1ShapedWitnessValues,
    },
    utils::{koalabear_bytes_to_bn254, koalabears_proof_nonce_to_bn254, words_to_bytes},
    witness::{OuterWitness, Witnessable},
    WrapConfig,
};
use sp1_recursion_compiler::config::InnerConfig;
use sp1_recursion_executor::{
    shape::RecursionShape, Block, ExecutionRecord, Executor, RecursionProgram,
    RecursionPublicValues, HASH_RATE, PERMUTATION_WIDTH,
};
use sp1_recursion_gnark_ffi::{Groth16Bn254Prover, PlonkBn254Prover};
use std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
};
use std::{io::Write, path::PathBuf};
use tokio::sync::{oneshot, OnceCell};
use tracing::Instrument;

/// The arities the binary recursion tree composes at: 1 (odd-node carry) and 2 (merge). Both the
/// within-chunk and across-chunk families are built for these.
const COMPOSE_ARITIES: [usize; 2] = [1, 2];

/// LRU capacity for compiled normalize programs (one per distinct core-proof shape).
const NORMALIZE_PROGRAM_CACHE_SIZE: usize = 16;

/// Configuration for the recursion prover.
#[derive(Debug, Clone)]
pub struct SP1RecursionProverConfig {
    /// The number of prepare reduce workers.
    pub num_prepare_reduce_workers: usize,
    /// The buffer size for the prepare reduce.
    pub prepare_reduce_buffer_size: usize,
    /// The number of recursion executor workers.
    pub num_recursion_executor_workers: usize,
    /// The buffer size for the recursion executor.
    pub recursion_executor_buffer_size: usize,
    /// The number of recursion prover workers.
    pub num_recursion_prover_workers: usize,
    /// The buffer size for the recursion prover.
    pub recursion_prover_buffer_size: usize,
    /// The maximum compose arity.
    pub max_compose_arity: usize,
    /// Whether to verify the recursion vks. Should be true by default and only can be set to false
    /// manually for code that is feature-gated behind the `experimental` flag.
    vk_verification: bool,
    /// Whether or not to verify the proof result at the end.
    pub verify_intermediates: bool,
    /// An optional file path for the vk map. Should be `None` by default and only can be set manually
    /// for code that is feature-gated behind the `experimental` flag.
    vk_map_file: Option<String>,
    /// The reduce shape
    pub reduce_shape: SP1RecursionProofShape,
}

impl SP1RecursionProverConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        num_prepare_reduce_workers: usize,
        prepare_reduce_buffer_size: usize,
        num_recursion_executor_workers: usize,
        recursion_executor_buffer_size: usize,
        num_recursion_prover_workers: usize,
        recursion_prover_buffer_size: usize,
        max_compose_arity: usize,
        verify_intermediates: bool,
        reduce_shape: SP1RecursionProofShape,
    ) -> Self {
        Self {
            num_prepare_reduce_workers,
            prepare_reduce_buffer_size,
            num_recursion_executor_workers,
            recursion_executor_buffer_size,
            num_recursion_prover_workers,
            recursion_prover_buffer_size,
            max_compose_arity,
            vk_verification: true,
            verify_intermediates,
            vk_map_file: None,
            reduce_shape,
        }
    }
    #[cfg(feature = "experimental")]
    /// Turn off vk verification for recursion proofs.
    pub fn without_vk_verification(self) -> Self {
        Self { vk_verification: false, ..self }
    }

    #[cfg(feature = "experimental")]
    /// Set the path to the recursion vk map.
    pub fn with_vk_map_path(self, vk_map_path: String) -> Self {
        Self { vk_map_file: Some(vk_map_path), ..self }
    }
}

pub struct ReduceTaskRequest {
    pub range_proofs: RangeProofs,
    pub is_complete: bool,
    pub output: Artifact,
    pub context: TaskContext,
}

impl ReduceTaskRequest {
    pub fn from_raw(request: RawTaskRequest) -> Result<Self, TaskError> {
        let RawTaskRequest { inputs, mut outputs, context } = request;
        let is_complete = inputs[0].id().parse::<bool>().map_err(|e| TaskError::Fatal(e.into()))?;
        let range_proofs = RangeProofs::from_artifacts(&inputs[1..])?;
        let output =
            outputs.pop().ok_or(TaskError::Fatal(anyhow::anyhow!("No output artifact")))?;
        Ok(ReduceTaskRequest { range_proofs, is_complete, output, context })
    }

    pub fn into_raw(self) -> Result<RawTaskRequest, TaskError> {
        let ReduceTaskRequest { range_proofs, is_complete, output, context } = self;
        let is_complete_artifact = Artifact::from(is_complete.to_string());
        let mut inputs = Vec::with_capacity(2 * range_proofs.len() + 2);
        inputs.push(is_complete_artifact);
        inputs.extend(range_proofs.as_artifacts());
        let raw_task_request = RawTaskRequest { inputs, outputs: vec![output], context };
        Ok(raw_task_request)
    }
}

pub struct PrepareReduceTaskWorker<A, C: SP1ProverComponents> {
    prover_data: Arc<RecursionProverData<C>>,
    artifact_client: A,
}

impl<A: ArtifactClient, C: SP1ProverComponents>
    AsyncWorker<ReduceTaskRequest, Result<RecursionTask, TaskError>>
    for PrepareReduceTaskWorker<A, C>
{
    #[tracing::instrument(level = "trace", name = "prepare_reduce_task", skip(self, input))]
    async fn call(&self, input: ReduceTaskRequest) -> Result<RecursionTask, TaskError> {
        let ReduceTaskRequest { range_proofs, is_complete, output, .. } = input;

        // The `RecursionReduce` task is the across-chunk reduce.
        let arity = range_proofs.len();
        let program = self.prover_data.compose_program(ComposeScope::AcrossChunk, arity).ok_or(
            TaskError::Fatal(anyhow::anyhow!(
                "Across-chunk compose program not found for arity {arity}"
            )),
        )?;

        let witness = range_proofs
            .download_witness::<C>(is_complete, &self.artifact_client, &self.prover_data)
            .await?;

        let metrics = ProverMetrics::new();
        Ok(RecursionTask {
            program,
            witness,
            output,
            metrics,
            range_proofs_to_cleanup: Some(range_proofs),
        })
    }
}

pub struct RecursionTask {
    program: Arc<RecursionProgram<SP1Field>>,
    witness: SP1CircuitWitness,
    range_proofs_to_cleanup: Option<RangeProofs>,
    output: Artifact,
    metrics: ProverMetrics,
}

pub struct RecursionExecutorWorker<C: SP1ProverComponents> {
    compress_verifier: MachineVerifier<SP1GlobalContext, RecursionSC>,
    prover_data: Arc<RecursionProverData<C>>,
    record_write_dir: Option<PathBuf>,
}

static RECORDS_WRITTEN: AtomicBool = AtomicBool::new(false);
static SHRINK_RECORDS_WRITTEN: AtomicBool = AtomicBool::new(false);

impl<C: SP1ProverComponents>
    BlockingWorker<Result<RecursionTask, TaskError>, Result<ProveRecursionTask<C>, TaskError>>
    for RecursionExecutorWorker<C>
{
    fn call(
        &self,
        input: Result<RecursionTask, TaskError>,
    ) -> Result<ProveRecursionTask<C>, TaskError> {
        let RecursionTask { program, witness, output, metrics, range_proofs_to_cleanup } = input?;

        // Execute the runtime.
        let runtime_span = tracing::debug_span!("execute runtime").entered();
        let mut runtime =
            Executor::<SP1Field, SP1ExtensionField, _>::new(program.clone(), inner_perm());
        runtime.witness_stream = self.prover_data.witness_stream(&witness)?;
        runtime.run().map_err(|e| TaskError::Fatal(e.into()))?;
        let mut record = runtime.record;
        runtime_span.exit();

        tokio::task::spawn_blocking(move || {
            drop(runtime.memory);
            drop(runtime.program);
            drop(runtime.witness_stream);
        });

        // Generate the dependencies.
        tracing::debug_span!("generate dependencies").in_scope(|| {
            self.compress_verifier
                .machine()
                .generate_dependencies(std::iter::once(&mut record), None)
        });

        let keys = tracing::debug_span!("get keys").in_scope(|| match witness {
            SP1CircuitWitness::Core(_) => anyhow::Ok(RecursionKeys::Program(program)),
            SP1CircuitWitness::Compress { witness: input, scope } => {
                let arity = input.compress_val.vks_and_proofs.len();
                let (pk, vk) =
                    self.prover_data.compose_keys(scope, arity).ok_or(TaskError::Fatal(
                        anyhow::anyhow!("Compose key not found for {scope:?} arity {arity}"),
                    ))?;
                if let Some(record_write_dir) = &self.record_write_dir {
                    if arity == DEFAULT_ARITY
                        && !RECORDS_WRITTEN.load(std::sync::atomic::Ordering::Relaxed)
                    {
                        let mut file =
                            std::fs::File::create(record_write_dir.join("max_arity_input.bin"))?;
                        let input_bytes = bincode::serialize(&input)?;
                        file.write_all(&input_bytes)?;
                        RECORDS_WRITTEN.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                anyhow::Ok(RecursionKeys::Exists(pk, vk))
            }
            SP1CircuitWitness::Deferred(_) => {
                let keys = self
                    .prover_data
                    .deferred_keys
                    .clone()
                    .map(|(pk, vk)| RecursionKeys::Exists(pk, vk))
                    .unwrap_or_else(|| {
                        RecursionKeys::Program(self.prover_data.deferred_program.clone())
                    });
                anyhow::Ok(keys)
            }
            _ => unimplemented!(),
        })?;

        Ok(ProveRecursionTask { record, keys, output, metrics, range_proofs_to_cleanup })
    }
}

pub type CompressProvingKey<C> =
    ProvingKey<SP1GlobalContext, RecursionSC, <C as SP1ProverComponents>::RecursionProver>;

enum RecursionKeys<C: SP1ProverComponents> {
    Exists(Arc<CompressProvingKey<C>>, MachineVerifyingKey<SP1GlobalContext>),
    Program(Arc<RecursionProgram<SP1Field>>),
}

pub struct ProveRecursionTask<C: SP1ProverComponents> {
    record: ExecutionRecord<SP1Field>,
    keys: RecursionKeys<C>,
    output: Artifact,
    metrics: ProverMetrics,
    range_proofs_to_cleanup: Option<RangeProofs>,
}

pub struct RecursionProverWorker<A, C: SP1ProverComponents> {
    recursion_prover: Arc<C::RecursionProver>,
    permits: ProverSemaphore,
    artifact_client: A,
    verify_intermediates: bool,
    prover_data: Arc<RecursionProverData<C>>,
}

impl<A: ArtifactClient, C: SP1ProverComponents> RecursionProverWorker<A, C> {
    async fn prove_shard(
        &self,
        keys: RecursionKeys<C>,
        record: ExecutionRecord<SP1Field>,
        metrics: ProverMetrics,
    ) -> Result<SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>, TaskError> {
        let proof = match keys {
            RecursionKeys::Exists(pk, vk) => {
                let (proof, permit) = self
                    .recursion_prover
                    .prove_shard_with_pk(pk.clone(), record, self.permits.clone())
                    .await;
                let duration = permit.release();
                metrics.increment_permit_time(duration);

                if self.verify_intermediates {
                    let proof = proof.clone();
                    let vk = vk.clone();
                    let parent = tracing::Span::current();
                    tokio::task::spawn_blocking(move || {
                        let _guard = parent.enter();
                        C::compress_verifier()
                            .verify(&vk, &MachineProof::from(vec![proof]))
                            .map_err(|e| {
                                TaskError::Retryable(anyhow::anyhow!(
                                    "compress verify failed: {}",
                                    e
                                ))
                            })
                    })
                    .await
                    .map_err(|e| TaskError::Fatal(e.into()))??;
                }
                let vk_merkle_proof = self.prover_data.recursion_vks.open(&vk)?.1;
                SP1RecursionProof { vk, proof, vk_merkle_proof }
            }
            RecursionKeys::Program(program) => {
                let (vk, proof, permit) = self
                    .recursion_prover
                    .setup_and_prove_shard(program, record, None, self.permits.clone())
                    .await;
                let duration = permit.release();
                metrics.increment_permit_time(duration);
                if self.verify_intermediates {
                    let proof = proof.clone();
                    let vk = vk.clone();
                    let parent = tracing::Span::current();
                    tokio::task::spawn_blocking(move || {
                        let _guard = parent.enter();
                        C::compress_verifier()
                            .verify(&vk, &MachineProof::from(vec![proof.clone()]))
                            .map_err(|e| {
                                TaskError::Retryable(anyhow::anyhow!(
                                    "lift/deferred verify failed: {}",
                                    e
                                ))
                            })
                    })
                    .await
                    .map_err(|e| TaskError::Fatal(e.into()))??;
                }
                let vk_merkle_proof = self.prover_data.recursion_vks.open(&vk)?.1;
                SP1RecursionProof { vk, proof, vk_merkle_proof }
            }
        };
        Ok(proof)
    }
}

impl<A: ArtifactClient, C: SP1ProverComponents>
    AsyncWorker<Result<ProveRecursionTask<C>, TaskError>, Result<TaskMetadata, TaskError>>
    for RecursionProverWorker<A, C>
{
    async fn call(
        &self,
        input: Result<ProveRecursionTask<C>, TaskError>,
    ) -> Result<TaskMetadata, TaskError> {
        // Get the input or return an error
        let ProveRecursionTask { record, keys, output, metrics, range_proofs_to_cleanup } = input?;
        // Prove the shard
        let proof = self.prove_shard(keys, record, metrics.clone()).await?;
        // Upload the proof

        self.artifact_client.upload(&output, proof.clone()).await?;
        let metadata = metrics.to_metadata();

        // Delete the proofs to cleanup.
        if let Some(proofs_to_cleanup) = range_proofs_to_cleanup {
            proofs_to_cleanup.try_delete_proofs(&self.artifact_client).await?;
        }

        Ok(metadata)
    }
}

type ExecutorEngine<C> = Arc<
    BlockingEngine<
        Result<RecursionTask, TaskError>,
        Result<ProveRecursionTask<C>, TaskError>,
        RecursionExecutorWorker<C>,
    >,
>;

type RecursionProverEngine<A, C> = Arc<
    AsyncEngine<
        Result<ProveRecursionTask<C>, TaskError>,
        Result<TaskMetadata, TaskError>,
        RecursionProverWorker<A, C>,
    >,
>;

type PrepareReduceEngine<A, C> = Arc<
    AsyncEngine<ReduceTaskRequest, Result<RecursionTask, TaskError>, PrepareReduceTaskWorker<A, C>>,
>;

type RecursionProvePipeline<A, C> = Chain<ExecutorEngine<C>, RecursionProverEngine<A, C>>;

type ReducePipeline<A, C> = Chain<PrepareReduceEngine<A, C>, Arc<RecursionProvePipeline<A, C>>>;

pub type RecursionProveSubmitHandle<A, C> = SubmitHandle<RecursionProvePipeline<A, C>>;

pub type ReduceSubmitHandle<A, C> = SubmitHandle<ReducePipeline<A, C>>;

pub struct SP1RecursionProver<A, C: SP1ProverComponents> {
    reduce_pipeline: Arc<ReducePipeline<A, C>>,
    pub shrink_prover: Arc<ShrinkProver<C>>,
    wrap_prover: Arc<OnceCell<Arc<WrapProver<C>>>>,
    wrap_prover_init: Arc<WrapProverInit<C>>,
    pub prover_data: Arc<RecursionProverData<C>>,
    artifact_client: A,
}

struct WrapProverInit<C: SP1ProverComponents> {
    wrap_air_prover: WrapAirProverInit<C>,
    config: SP1RecursionProverConfig,
    shrink_shape: BTreeMap<String, usize>,
    expected_wrap_vk: MachineVerifyingKey<SP1OuterGlobalContext>,
}

impl<A: Clone, C: SP1ProverComponents> Clone for SP1RecursionProver<A, C> {
    fn clone(&self) -> Self {
        Self {
            reduce_pipeline: self.reduce_pipeline.clone(),
            shrink_prover: self.shrink_prover.clone(),
            wrap_prover: self.wrap_prover.clone(),
            wrap_prover_init: self.wrap_prover_init.clone(),
            prover_data: self.prover_data.clone(),
            artifact_client: self.artifact_client.clone(),
        }
    }
}

impl<A: ArtifactClient, C: SP1ProverComponents> SP1RecursionProver<A, C> {
    pub async fn new(
        config: SP1RecursionProverConfig,
        machine: Machine<SP1Field, RiscvAir<SP1Field>>,
        artifact_client: A,
        (compress_prover, compress_prover_permits): (Arc<C::RecursionProver>, ProverSemaphore),
        (shrink_prover, shrink_prover_permits): (Arc<C::RecursionProver>, ProverSemaphore),
        wrap_air_prover_init: WrapAirProverInit<C>,
    ) -> Self {
        tokio::task::spawn_blocking(move || {
            // Get the reduce shape.
            let reduce_shape = config.reduce_shape.clone();

            let vk_map_path = config.vk_map_file.as_ref().map(std::path::PathBuf::from);

            let recursion_vks =
                RecursionVks::new(vk_map_path, config.max_compose_arity, config.vk_verification);

            let recursion_vks_height = recursion_vks.height();

            let compress_verifier = C::compress_verifier();
            let recursive_compress_verifier =
                recursive_verifier::<SP1GlobalContext, _,  InnerConfig>(
                    compress_verifier.shard_verifier(),
                );

            // Build one compose program + keys for the given arity and family. The binary recursion
            // tree only ever merges 1 (odd-node carry) or 2 children.
            let build_compose = |arity: usize, scope: ComposeScope| {
                let dummy_input =
                    dummy_compose_input::<C>(&reduce_shape, arity, recursion_vks_height);
                let mut program = match scope {
                    ComposeScope::WithinChunk => chunk_compose_program_from_input(
                        &recursive_compress_verifier,
                        config.vk_verification,
                        &dummy_input,
                    ),
                    ComposeScope::AcrossChunk => global_compose_program_from_input(
                        &recursive_compress_verifier,
                        config.vk_verification,
                        &dummy_input,
                    ),
                };
                program.shape = Some(reduce_shape.shape.clone());
                let program = Arc::new(program);

                let (tx, rx) = oneshot::channel();
                tokio::task::spawn({
                    let program = program.clone();
                    let air_prover = compress_prover.clone();
                    async move {
                        let permits = ProverSemaphore::new(1);
                        let (pk, vk) = air_prover.setup(program, permits).await;
                        tx.send((pk, vk)).ok();
                    }
                });
                let (pk, vk) = rx.blocking_recv().unwrap();
                let pk = unsafe { pk.into_inner() };
                (program, (pk, vk))
            };

            let mut within_chunk_compose_programs = BTreeMap::new();
            let mut within_chunk_compose_keys = BTreeMap::new();
            let mut across_chunk_compose_programs = BTreeMap::new();
            let mut across_chunk_compose_keys = BTreeMap::new();
            for arity in COMPOSE_ARITIES {
                let (program, keys) = build_compose(arity, ComposeScope::WithinChunk);
                within_chunk_compose_programs.insert(arity, program);
                within_chunk_compose_keys.insert(arity, keys);
                let (program, keys) = build_compose(arity, ComposeScope::AcrossChunk);
                across_chunk_compose_programs.insert(arity, program);
                across_chunk_compose_keys.insert(arity, keys);
            }

            // Build the normalize program family: programs are compiled per core-proof
            // shape on demand and cached, so only the compiler is held here.
            let normalize = {
                let core_verifier = C::core_verifier(machine);
                let recursive_core_verifier = recursive_verifier::<SP1GlobalContext, _, InnerConfig>(
                    core_verifier.shard_verifier(),
                );
                let cache = SP1NormalizeCache::new(NORMALIZE_PROGRAM_CACHE_SIZE);
                NormalizeProgramCompiler::new(
                    cache,
                    recursive_core_verifier,
                    reduce_shape.clone(),
                    core_verifier,
                )
            };

            // Make the deferred program and keys.
            let deferred_input =
                dummy_deferred_input(&compress_verifier, &reduce_shape, recursion_vks_height);
            let mut deferred_program = deferred_program_from_input(
                &recursive_compress_verifier,
                config.vk_verification,
                &deferred_input,
            );
            deferred_program.shape = Some(reduce_shape.shape.clone());
            let deferred_program = Arc::new(deferred_program);
            let (tx, rx) = oneshot::channel();
            tokio::task::spawn({
                let program = deferred_program.clone();
                let air_prover = compress_prover.clone();
                async move {
                    let permits = ProverSemaphore::new(1);
                    let (pk, vk) = air_prover.setup(program, permits).await;
                    tx.send((pk, vk)).ok();
                }
            });
            let (pk, vk) = rx.blocking_recv().unwrap();
            let pk = unsafe { pk.into_inner() };
            let deferred_keys = (pk, vk);

            let prover_data = Arc::new(RecursionProverData {
                recursion_vks,
                reduce_shape,
                normalize,
                within_chunk_compose_programs,
                within_chunk_compose_keys,
                across_chunk_compose_programs,
                across_chunk_compose_keys,
                deferred_program,
                deferred_keys: Some(deferred_keys),
            });

            let compress_verifier = C::compress_verifier();

            // Initialize the prepare reduce engine.
            let prepare_reduce_workers = (0..config.num_prepare_reduce_workers)
                .map(|_| PrepareReduceTaskWorker {
                    prover_data: prover_data.clone(),
                    artifact_client: artifact_client.clone(),
                })
                .collect();
            let prepare_reduce_engine = Arc::new(AsyncEngine::new(
                prepare_reduce_workers,
                config.prepare_reduce_buffer_size,
            ));

            let record_write_dir =
                std::env::var("SP1_RECORD_MAX_ARITY_INPUT").ok().map(PathBuf::from);

            // Initialize the executor engine.
            let executor_workers = (0..config.num_recursion_executor_workers)
                .map(|_| RecursionExecutorWorker {
                    compress_verifier: compress_verifier.clone(),
                    prover_data: prover_data.clone(),
                    record_write_dir: record_write_dir.clone(),
                })
                .collect();

            let executor_engine = Arc::new(BlockingEngine::new(
                executor_workers,
                config.recursion_executor_buffer_size,
            ));

            // Initialize the prove engine.
            let prove_workers = (0..config.num_recursion_prover_workers)
                .map(|_| RecursionProverWorker {
                    prover_data: prover_data.clone(),
                    recursion_prover: compress_prover.clone(),
                    permits: compress_prover_permits.clone(),
                    artifact_client: artifact_client.clone(),
                    verify_intermediates: config.verify_intermediates,
                })
                .collect();
            let prove_engine =
                Arc::new(AsyncEngine::new(prove_workers, config.recursion_prover_buffer_size));

            // Make the recursion pipeline.
            let recursion_pipeline = Arc::new(Chain::new(executor_engine, prove_engine));

            // Make the reduce pipeline.
            let reduce_pipeline = Arc::new(Chain::new(prepare_reduce_engine, recursion_pipeline));

            let shrink_prover = Arc::new(ShrinkProver::new(
                shrink_prover,
                shrink_prover_permits,
                prover_data.clone(),
                config.clone(),
            ));

            let expected_wrap_vk = bincode::deserialize(WRAP_VK_BYTES).unwrap();
            let wrap_prover_init = WrapProverInit {
                wrap_air_prover: wrap_air_prover_init,
                config: config.clone(),
                shrink_shape: shrink_prover.shrink_shape.clone(),
                expected_wrap_vk,
            };

            Self {
                reduce_pipeline,
                shrink_prover,
                wrap_prover: Arc::new(OnceCell::new()),
                wrap_prover_init: Arc::new(wrap_prover_init),
                prover_data,
                artifact_client,
            }
        })
        .await
        .unwrap()
    }

    pub fn recursion_prover_pipeline(&self) -> &Arc<RecursionProvePipeline<A, C>> {
        self.reduce_pipeline.second()
    }

    pub async fn submit_prove_shard(
        &self,
        program: Arc<RecursionProgram<SP1Field>>,
        witness: SP1CircuitWitness,
        output: Artifact,
        metrics: ProverMetrics,
    ) -> Result<RecursionProveSubmitHandle<A, C>, SubmitError> {
        self.recursion_prover_pipeline()
            .submit(Ok(RecursionTask {
                program,
                witness,
                output,
                metrics,
                range_proofs_to_cleanup: None,
            }))
            .await
    }

    pub async fn submit_recursion_reduce(
        &self,
        request: RawTaskRequest,
    ) -> Result<ReduceSubmitHandle<A, C>, TaskError> {
        let input = ReduceTaskRequest::from_raw(request)?;
        let handle = self.reduce_pipeline.submit(input).await?;
        Ok(handle)
    }

    async fn wrap_prover(&self) -> Result<Arc<WrapProver<C>>, TaskError> {
        let wrap_prover_init = self.wrap_prover_init.clone();
        let prover_data = self.prover_data.clone();

        let wrap_prover = self
            .wrap_prover
            .get_or_try_init(|| async move {
                let wrap_prover_init = wrap_prover_init.clone();
                let prover_data = prover_data.clone();
                tokio::task::spawn_blocking(move || {
                    let expected_wrap_vk = wrap_prover_init.expected_wrap_vk.clone();
                    let wrap_air_prover = wrap_prover_init.wrap_air_prover.build();
                    let wrap_air_permits = wrap_prover_init.wrap_air_prover.permits();
                    let wrap_prover = WrapProver::new(
                        wrap_air_prover,
                        wrap_air_permits,
                        prover_data,
                        wrap_prover_init.config.clone(),
                        wrap_prover_init.shrink_shape.clone(),
                    );

                    if wrap_prover.prover_data.recursion_vks.vk_verification()
                        && wrap_prover.verifying_key != expected_wrap_vk
                    {
                        return Err(TaskError::Fatal(anyhow::anyhow!(
                            "Wrap vk mismatch, expected: {:?}, got: {:?}",
                            expected_wrap_vk,
                            wrap_prover.verifying_key
                        )));
                    }

                    Ok(Arc::new(wrap_prover))
                })
                .await
                .map_err(|err| TaskError::Fatal(anyhow::anyhow!(err)))?
            })
            .await?;

        Ok(wrap_prover.clone())
    }

    pub async fn run_shrink_wrap(&self, request: RawTaskRequest) -> Result<(), TaskError> {
        let RawTaskRequest { inputs, outputs, .. } = request;
        let [compress_proof_artifact] = inputs.try_into().unwrap();
        let [wrap_proof_artifact] = outputs.try_into().unwrap();

        let compress_proof = self
            .artifact_client
            .download(&compress_proof_artifact)
            .instrument(tracing::debug_span!("download compress proof"))
            .await?;

        let shrink_proof = self
            .shrink_prover
            .prove(compress_proof)
            .instrument(tracing::info_span!("prove shrink"))
            .await?;

        tracing::debug_span!("verify shrink proof")
            .in_scope(|| self.shrink_prover.verify(&shrink_proof))?;

        let wrap_prover = self.wrap_prover().await?;
        let wrap_proof =
            wrap_prover.prove(shrink_proof).instrument(tracing::info_span!("prove wrap")).await?;

        tracing::debug_span!("verify wrap proof").in_scope(|| wrap_prover.verify(&wrap_proof))?;

        self.artifact_client
            .upload(&wrap_proof_artifact, wrap_proof)
            .instrument(tracing::debug_span!("upload wrap proof"))
            .await?;

        Ok(())
    }

    pub async fn run_groth16(&self, request: RawTaskRequest) -> Result<(), TaskError> {
        let RawTaskRequest { inputs, outputs, .. } = request;
        let [wrap_proof_artifact] = inputs.try_into().unwrap();
        let [groth16_proof_artifact] = outputs.try_into().unwrap();

        let wrap_proof: SP1WrapProof<SP1OuterGlobalContext, SP1PcsProofOuter> = self
            .artifact_client
            .download(&wrap_proof_artifact)
            .instrument(tracing::debug_span!("download wrap proof"))
            .await?;

        let build_dir = try_build_groth16_artifacts_dir(&wrap_proof.vk, &wrap_proof.proof)
            .await
            .map_err(TaskError::Fatal)?;

        let groth16_proof = tokio::task::spawn_blocking(move || -> Result<_, anyhow::Error> {
            let SP1WrapProof { vk, proof } = wrap_proof;
            let input = SP1ShapedWitnessValues {
                vks_and_proofs: vec![(vk, proof.clone())],
                is_complete: true,
            };
            let pv: &RecursionPublicValues<SP1Field> = proof.public_values.as_slice().borrow();
            let vkey_hash = koalabears_to_bn254(&pv.sp1_vk_digest);
            let committed_values_digest_bytes: [SP1Field; 32] =
                words_to_bytes(&pv.committed_value_digest).try_into().map_err(|_| {
                    anyhow::anyhow!(
                        "committed_value_digest has invalid length, expected exactly 32 elements"
                    )
                })?;
            let committed_values_digest = koalabear_bytes_to_bn254(&committed_values_digest_bytes);
            let exit_code = Bn254Fr::from_canonical_u32(pv.exit_code.as_canonical_u32());
            let proof_nonce = koalabears_proof_nonce_to_bn254(&pv.proof_nonce);
            let vk_root = koalabears_to_bn254(&pv.vk_root);
            let witness = {
                let mut witness = OuterWitness::default();
                input.write(&mut witness);
                witness.write_committed_values_digest(committed_values_digest);
                witness.write_vkey_hash(vkey_hash);
                witness.write_exit_code(exit_code);
                witness.write_vk_root(vk_root);
                witness.write_proof_nonce(proof_nonce);
                witness
            };
            let prover = Groth16Bn254Prover::new();
            let proof = prover.prove(witness, &build_dir);
            prover
                .verify(
                    &proof,
                    &vkey_hash.as_canonical_biguint(),
                    &committed_values_digest.as_canonical_biguint(),
                    &exit_code.as_canonical_biguint(),
                    &vk_root.as_canonical_biguint(),
                    &proof_nonce.as_canonical_biguint(),
                    &build_dir,
                )
                .map_err(|e| anyhow::anyhow!("Failed to verify groth16 wrap proof: {}", e))?;
            Ok(proof)
        })
        .instrument(tracing::info_span!("prove groth16"))
        .await
        .map_err(|e| TaskError::Fatal(anyhow::anyhow!("Groth16 proof task panicked: {}", e)))?
        .map_err(TaskError::Fatal)?;

        self.artifact_client
            .upload(&groth16_proof_artifact, groth16_proof)
            .instrument(tracing::debug_span!("upload groth16 proof"))
            .await?;
        Ok(())
    }

    pub async fn run_plonk(&self, request: RawTaskRequest) -> Result<(), TaskError> {
        let RawTaskRequest { inputs, outputs, .. } = request;
        let [wrap_proof_artifact] = inputs.try_into().unwrap();
        let [plonk_proof_artifact] = outputs.try_into().unwrap();
        let wrap_proof: SP1WrapProof<SP1OuterGlobalContext, SP1PcsProofOuter> = self
            .artifact_client
            .download(&wrap_proof_artifact)
            .instrument(tracing::debug_span!("download wrap proof"))
            .await?;

        let build_dir = try_build_plonk_artifacts_dir(&wrap_proof.vk, &wrap_proof.proof).await?;

        let plonk_proof = tokio::task::spawn_blocking(move || -> Result<_, anyhow::Error> {
            let SP1WrapProof { vk: wrap_vk, proof: wrap_proof } = wrap_proof;
            let input = SP1ShapedWitnessValues {
                vks_and_proofs: vec![(wrap_vk.clone(), wrap_proof.clone())],
                is_complete: true,
            };
            let pv: &RecursionPublicValues<SP1Field> = wrap_proof.public_values.as_slice().borrow();
            let vkey_hash = koalabears_to_bn254(&pv.sp1_vk_digest);
            let committed_values_digest_bytes: [SP1Field; 32] =
                words_to_bytes(&pv.committed_value_digest).try_into().map_err(|_| {
                    anyhow::anyhow!(
                        "committed_value_digest has invalid length, expected exactly 32 elements"
                    )
                })?;
            let committed_values_digest = koalabear_bytes_to_bn254(&committed_values_digest_bytes);
            let exit_code = Bn254Fr::from_canonical_u32(pv.exit_code.as_canonical_u32());
            let vk_root = koalabears_to_bn254(&pv.vk_root);
            let proof_nonce = koalabears_proof_nonce_to_bn254(&pv.proof_nonce);
            let witness = {
                let mut witness = OuterWitness::default();
                input.write(&mut witness);
                witness.write_committed_values_digest(committed_values_digest);
                witness.write_vkey_hash(vkey_hash);
                witness.write_exit_code(exit_code);
                witness.write_vk_root(vk_root);
                witness.write_proof_nonce(proof_nonce);
                witness
            };
            let prover = PlonkBn254Prover::new();
            let proof = prover.prove(witness, &build_dir);
            prover
                .verify(
                    &proof,
                    &vkey_hash.as_canonical_biguint(),
                    &committed_values_digest.as_canonical_biguint(),
                    &exit_code.as_canonical_biguint(),
                    &vk_root.as_canonical_biguint(),
                    &proof_nonce.as_canonical_biguint(),
                    &build_dir,
                )
                .map_err(|e| anyhow::anyhow!("Failed to verify plonk wrap proof: {}", e))?;
            Ok(proof)
        })
        .instrument(tracing::info_span!("prove plonk"))
        .await
        .map_err(|e| TaskError::Fatal(anyhow::anyhow!("Plonk proof task panicked: {}", e)))?
        .map_err(TaskError::Fatal)?;

        self.artifact_client
            .upload(&plonk_proof_artifact, plonk_proof)
            .instrument(tracing::debug_span!("upload plonk proof"))
            .await?;
        Ok(())
    }

    #[inline]
    #[must_use]
    pub fn recursion_vk_root(&self) -> [SP1Field; DIGEST_SIZE] {
        self.prover_data.recursion_vks.root()
    }

    #[must_use]
    pub fn vk_verification(&self) -> bool {
        self.prover_data.vk_verification()
    }

    #[must_use]
    pub fn get_normalize_witness(
        &self,
        common_input: &CommonProverInput,
        proof: &ShardProof<SP1GlobalContext, SP1PcsProofInner>,
        chunk_ctx: &ChunkChallengeCtx,
        is_complete: bool,
        is_precompile: bool,
    ) -> SP1NormalizeWitnessValues<SP1GlobalContext, SP1PcsProofInner> {
        // Use the final deferred digest from common_input for reconstruct_deferred_digest.
        // This is needed because:
        // - For core and global memory shards: deferred_proofs_digest equals
        //   common_input.deferred_digest and the number of deferred proofs accumulated so far is
        //   the total number of deferred proofs.
        // - For precompile shards: they are ordered first in the deferred tree so their number
        //   of accumulated deferred proofs is 0 and deferred_proofs_digest is the initial digest
        let (num_deferred_proofs, reconstruct_deferred_digest) = if is_precompile {
            (SP1Field::zero(), DeferredInputs::initial_deferred_digest())
        } else {
            (
                SP1Field::from_canonical_usize(common_input.num_deferred_proofs),
                common_input.deferred_digest.map(SP1Field::from_canonical_u32),
            )
        };
        // `H = hash_iter(commitments)` binds the chunk's shared global challenge, mirroring
        // `observe_global_challenge`. The circuit re-derives the challenge by observing `H`.
        let (hasher, _) = SP1GlobalContext::default_hasher_and_compressor();
        let commitments_hash = hasher
            .hash_iter(chunk_ctx.commitments.iter().flat_map(SP1GlobalContext::digest_to_elements));
        // Running hash state before this shard folds in its own commitment.
        let mut prev_hasher_state = [SP1Field::zero(); PERMUTATION_WIDTH];
        for c in &chunk_ctx.commitments[..chunk_ctx.shard_index as usize] {
            prev_hasher_state[..HASH_RATE]
                .copy_from_slice(&SP1GlobalContext::digest_to_elements(c));
            inner_perm().permute_mut(&mut prev_hasher_state);
        }
        SP1NormalizeWitnessValues {
            vk: common_input.vk.vk.clone(),
            shard_proofs: vec![proof.clone()],
            is_complete,
            vk_root: self.recursion_vk_root(),
            reconstruct_deferred_digest,
            num_deferred_proofs,
            commitments_hash: SP1GlobalContext::digest_to_elements(&commitments_hash)
                .try_into()
                .expect("commitments hash has DIGEST_SIZE elements"),
            prev_root: chunk_ctx.prev_root.map(SP1Field::from_canonical_u32),
            cur_root: chunk_ctx.cur_root.map(SP1Field::from_canonical_u32),
            shard_index: SP1Field::from_canonical_u32(chunk_ctx.shard_index),
            num_shards: SP1Field::from_canonical_u32(chunk_ctx.num_shards),
            prev_hasher_state,
        }
    }

    pub fn reduce_shape(&self) -> &SP1RecursionProofShape {
        &self.prover_data.reduce_shape
    }

    /// Submit a recursion program + witness, wait for it, and return the proof. The prove worker
    /// uploads the proof to `out`, so we hand the same artifact back after the task completes.
    async fn prove_recursion_proof(
        &self,
        program: Arc<RecursionProgram<SP1Field>>,
        witness: SP1CircuitWitness,
        out: Artifact,
    ) -> Result<SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>, TaskError> {
        let metrics = ProverMetrics::new();
        self.submit_prove_shard(program, witness, out.clone(), metrics)
            .await?
            .await
            .map_err(|e| TaskError::Fatal(e.into()))??;
        let proof = self
            .artifact_client
            .download::<SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>>(&out)
            .await?;
        Ok(proof)
    }

    /// Assemble a scope-tagged compress witness from child recursion proofs.
    fn compose_witness(
        &self,
        children: Vec<SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>>,
        is_complete: bool,
        scope: ComposeScope,
    ) -> Result<SP1CircuitWitness, TaskError> {
        let (vks_and_proofs, merkle_proofs): (Vec<_>, Vec<_>) = children
            .into_iter()
            .map(|proof| ((proof.vk, proof.proof), proof.vk_merkle_proof))
            .unzip();
        let shaped = SP1ShapedWitnessValues { vks_and_proofs, is_complete };
        let witness = self.prover_data.append_merkle_proofs_to_witness(shaped, merkle_proofs)?;
        Ok(SP1CircuitWitness::Compress { witness, scope })
    }

    /// Reduce child proofs with the compose family selected by `scope`.
    async fn compose_reduce(
        &self,
        children: Vec<SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>>,
        is_complete: bool,
        scope: ComposeScope,
        out: Artifact,
    ) -> Result<SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>, TaskError> {
        let arity = children.len();
        let program = self.prover_data.compose_program(scope, arity).ok_or_else(|| {
            TaskError::Fatal(anyhow::anyhow!(
                "{scope:?} compose program not found for arity {arity}"
            ))
        })?;
        let witness = self.compose_witness(children, is_complete, scope)?;
        self.prove_recursion_proof(program, witness, out).await
    }
}

impl<A: ArtifactClient, C: SP1ProverComponents> RecursionStages for SP1RecursionProver<A, C> {
    fn normalize<'a>(
        &'a self,
        common: &'a CommonProverInput,
        core_proof: ShardProof<SP1GlobalContext, SP1PcsProofInner>,
        chunk_ctx: &'a ChunkChallengeCtx,
        out: Artifact,
    ) -> BoxFuture<'a, Result<SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>, TaskError>>
    {
        Box::pin(async move {
            let program =
                self.prover_data.normalize.program_for_proof(common.vk.clone(), &core_proof);
            let witness = self.get_normalize_witness(common, &core_proof, chunk_ctx, false, false);
            self.prove_recursion_proof(program, SP1CircuitWitness::Core(witness), out).await
        })
    }

    fn within_chunk_reduce<'a>(
        &'a self,
        children: Vec<SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>>,
        is_chunk_complete: bool,
        out: Artifact,
    ) -> BoxFuture<'a, Result<SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>, TaskError>>
    {
        Box::pin(self.compose_reduce(children, is_chunk_complete, ComposeScope::WithinChunk, out))
    }
}

type CompressKeys<C> = (
    Arc<ProvingKey<SP1GlobalContext, RecursionSC, <C as SP1ProverComponents>::RecursionProver>>,
    MachineVerifyingKey<SP1GlobalContext>,
);

pub struct RecursionProverData<C: SP1ProverComponents> {
    recursion_vks: RecursionVks,
    reduce_shape: SP1RecursionProofShape,
    normalize: NormalizeProgramCompiler,
    within_chunk_compose_programs: BTreeMap<usize, Arc<RecursionProgram<SP1Field>>>,
    within_chunk_compose_keys: BTreeMap<usize, CompressKeys<C>>,
    across_chunk_compose_programs: BTreeMap<usize, Arc<RecursionProgram<SP1Field>>>,
    across_chunk_compose_keys: BTreeMap<usize, CompressKeys<C>>,
    deferred_program: Arc<RecursionProgram<SP1Field>>,
    deferred_keys: Option<CompressKeys<C>>,
}

impl<C: SP1ProverComponents> RecursionProverData<C> {
    pub fn vk_verification(&self) -> bool {
        self.recursion_vks.vk_verification()
    }

    pub fn recursion_vks(&self) -> &RecursionVks {
        &self.recursion_vks
    }

    /// The compose program for a (`scope`, `arity`); `None` if that family has no entry for the
    /// arity (the binary tree only ever asks for 1 or 2).
    pub(crate) fn compose_program(
        &self,
        scope: ComposeScope,
        arity: usize,
    ) -> Option<Arc<RecursionProgram<SP1Field>>> {
        match scope {
            ComposeScope::WithinChunk => self.within_chunk_compose_programs.get(&arity),
            ComposeScope::AcrossChunk => self.across_chunk_compose_programs.get(&arity),
        }
        .cloned()
    }

    /// The compose proving/verifying keys for a (`scope`, `arity`).
    pub(crate) fn compose_keys(
        &self,
        scope: ComposeScope,
        arity: usize,
    ) -> Option<CompressKeys<C>> {
        match scope {
            ComposeScope::WithinChunk => self.within_chunk_compose_keys.get(&arity),
            ComposeScope::AcrossChunk => self.across_chunk_compose_keys.get(&arity),
        }
        .cloned()
    }

    pub fn append_merkle_proofs_to_witness(
        &self,
        input: SP1ShapedWitnessValues<SP1GlobalContext, SP1PcsProofInner>,
        merkle_proofs: Vec<MerkleProof<SP1GlobalContext>>,
    ) -> Result<SP1CompressWithVKeyWitnessValues<SP1PcsProofInner>, TaskError> {
        let values = if self.recursion_vks.vk_verification() {
            input.vks_and_proofs.iter().map(|(vk, _)| vk.hash_koalabear()).collect()
        } else {
            let num_vks = self.recursion_vks.num_keys();
            input
                .vks_and_proofs
                .iter()
                .map(|(vk, _)| {
                    let vk_digest = vk.hash_koalabear();
                    let index = (vk_digest[0].as_canonical_u32() as usize) % num_vks;
                    [SP1Field::from_canonical_u32(index as u32); DIGEST_SIZE]
                })
                .collect()
        };

        let merkle_val = SP1MerkleProofWitnessValues {
            root: self.recursion_vks.root(),
            values,
            vk_merkle_proofs: merkle_proofs,
        };

        Ok(SP1CompressWithVKeyWitnessValues { compress_val: input, merkle_val })
    }

    pub fn witness_stream(
        &self,
        witness: &SP1CircuitWitness,
    ) -> Result<VecDeque<Block<SP1Field>>, TaskError> {
        let mut witness_stream = Vec::new();
        match witness {
            SP1CircuitWitness::Core(input) => {
                Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
            }
            SP1CircuitWitness::Deferred(input) => {
                Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
            }
            SP1CircuitWitness::Compress { witness, .. } => {
                Witnessable::<InnerConfig>::write(&witness, &mut witness_stream);
            }
            SP1CircuitWitness::Shrink(input) => {
                Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
            }
            SP1CircuitWitness::Wrap(input) => {
                Witnessable::<WrapConfig>::write(&input, &mut witness_stream);
            }
        }
        Ok(witness_stream.into())
    }

    pub fn deferred_program(&self) -> &Arc<RecursionProgram<SP1Field>> {
        &self.deferred_program
    }
}

fn dummy_compose_input<C: SP1ProverComponents>(
    shape: &SP1RecursionProofShape,
    arity: usize,
    height: usize,
) -> SP1CompressWithVKeyWitnessValues<SP1PcsProofInner> {
    let verifier = C::compress_verifier();
    shape.dummy_input(
        arity,
        height,
        verifier.shard_verifier().machine().chips().iter().cloned().collect::<BTreeSet<_>>(),
        verifier.max_log_row_count(),
        *verifier.fri_config(),
        verifier.log_stacking_height() as usize,
    )
}

pub struct ShrinkProver<C: SP1ProverComponents> {
    prover: Arc<C::RecursionProver>,
    permits: ProverSemaphore,
    program: Arc<RecursionProgram<SP1Field>>,
    pub verifying_key: MachineVerifyingKey<SP1GlobalContext>,
    prover_data: Arc<RecursionProverData<C>>,
    pub shrink_shape: BTreeMap<String, usize>,
    pub record_write_dir: Option<PathBuf>,
}

impl<C: SP1ProverComponents> ShrinkProver<C> {
    fn new(
        prover: Arc<C::RecursionProver>,
        permits: ProverSemaphore,
        prover_data: Arc<RecursionProverData<C>>,
        config: SP1RecursionProverConfig,
    ) -> Self {
        let verifier = C::compress_verifier();
        let input = prover_data.reduce_shape.dummy_input(
            1,
            prover_data.recursion_vks.height(),
            verifier.shard_verifier().machine().chips().iter().cloned().collect::<BTreeSet<_>>(),
            verifier.max_log_row_count(),
            *verifier.fri_config(),
            verifier.log_stacking_height() as usize,
        );
        let program = Arc::new(shrink_program_from_input(
            &recursive_verifier(verifier.shard_verifier()),
            config.vk_verification,
            &input,
        ));

        let (pk, vk) = {
            let (prover, program, permits) = (prover.clone(), program.clone(), permits.clone());
            let (tx, rx) = oneshot::channel();
            tokio::task::spawn(async move {
                tx.send(prover.setup(program.clone(), permits.clone()).await).ok()
            });
            rx.blocking_recv().unwrap()
        };
        let shrink_shape = {
            let (tx, rx) = oneshot::channel();
            tokio::task::spawn(async move {
                let heights = <C::RecursionProver as AirProver<
                    SP1GlobalContext,_
                >>::preprocessed_table_heights(pk.pk)
                .await;
                tx.send(heights).ok();
            });
            rx.blocking_recv().unwrap()
        };

        let record_write_dir = std::env::var("SP1_RECORD_SHRINK_INPUT").ok().map(PathBuf::from);

        Self {
            prover,
            permits,
            program,
            verifying_key: vk,
            prover_data,
            shrink_shape,
            record_write_dir,
        }
    }

    pub(crate) async fn setup(
        self: Arc<Self>,
        program: Arc<RecursionProgram<SP1Field>>,
    ) -> MachineVerifyingKey<SP1GlobalContext> {
        self.prover.setup(program, self.permits.clone()).await.1
    }

    async fn prove(
        &self,
        compressed_proof: SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>,
    ) -> Result<SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>, TaskError> {
        let execution_record = {
            let mut runtime =
                Executor::<SP1Field, SP1ExtensionField, _>::new(self.program.clone(), inner_perm());
            let SP1RecursionProof { vk, proof, vk_merkle_proof } = compressed_proof;
            let shaped_input =
                SP1ShapedWitnessValues { vks_and_proofs: vec![(vk, proof)], is_complete: true };
            let shrink_input = self
                .prover_data
                .append_merkle_proofs_to_witness(shaped_input, vec![vk_merkle_proof])?;

            if let Some(record_write_dir) = &self.record_write_dir {
                if !SHRINK_RECORDS_WRITTEN.load(std::sync::atomic::Ordering::Relaxed) {
                    let mut file = std::fs::File::create(record_write_dir.join("shrink_input.bin"))
                        .map_err(|e| TaskError::Fatal(e.into()))?;
                    let input_bytes = bincode::serialize(&shrink_input)
                        .map_err(|e| TaskError::Fatal(e.into()))?;
                    file.write_all(&input_bytes).map_err(|e| TaskError::Fatal(e.into()))?;
                    SHRINK_RECORDS_WRITTEN.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }

            runtime.witness_stream =
                self.prover_data.witness_stream(&SP1CircuitWitness::Shrink(shrink_input))?;
            runtime.run().map_err(|e| TaskError::Fatal(e.into()))?;
            runtime.record
        };

        let (vk, proof, _permit) = self
            .prover
            .setup_and_prove_shard(
                self.program.clone(),
                execution_record,
                Some(self.verifying_key.clone()),
                self.permits.clone(),
            )
            .await;
        let vk_merkle_proof = self.prover_data.recursion_vks.open(&vk)?.1;
        Ok(SP1RecursionProof { vk: self.verifying_key.clone(), proof, vk_merkle_proof })
    }

    fn verify(
        &self,
        shrink_proof: &SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>,
    ) -> Result<(), TaskError> {
        let SP1RecursionProof { vk, proof, vk_merkle_proof } = shrink_proof;
        let mut challenger = SP1GlobalContext::default_challenger();
        vk.observe_into(&mut challenger);
        C::shrink_verifier()
            .verify_shard(vk, proof, &mut challenger)
            .map_err(|e| TaskError::Fatal(e.into()))?;

        self.prover_data.recursion_vks.verify(vk_merkle_proof, vk)
    }
}

pub struct WrapProver<C: SP1ProverComponents> {
    prover: Arc<C::WrapProver>,
    permits: ProverSemaphore,
    program: Arc<RecursionProgram<SP1Field>>,
    pub verifying_key: MachineVerifyingKey<SP1OuterGlobalContext>,
    prover_data: Arc<RecursionProverData<C>>,
}

impl<C: SP1ProverComponents> WrapProver<C> {
    pub fn new(
        prover: Arc<C::WrapProver>,
        permits: ProverSemaphore,
        prover_data: Arc<RecursionProverData<C>>,
        config: SP1RecursionProverConfig,
        shrink_shape: BTreeMap<String, usize>,
    ) -> Self {
        let verifier = C::shrink_verifier();
        let shrink_proof_shape =
            SP1RecursionProofShape { shape: RecursionShape::new(shrink_shape) };
        let wrap_input = shrink_proof_shape.dummy_input(
            1,
            prover_data.recursion_vks.height(),
            verifier.shard_verifier().machine().chips().iter().cloned().collect::<BTreeSet<_>>(),
            verifier.max_log_row_count(),
            *verifier.fri_config(),
            verifier.log_stacking_height() as usize,
        );

        let program = Arc::new(wrap_program_from_input(
            &recursive_verifier(verifier.shard_verifier()),
            config.vk_verification,
            &wrap_input,
        ));
        let (_, verifying_key) = {
            let (prover, program, permits) = (prover.clone(), program.clone(), permits.clone());
            let (tx, rx) = oneshot::channel();
            tokio::task::spawn(async move {
                tx.send(prover.setup(program.clone(), permits).await).ok();
            });
            rx.blocking_recv().unwrap()
        };

        Self { prover, permits, program, verifying_key, prover_data }
    }

    pub async fn prove(
        &self,
        shrunk_proof: SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>,
    ) -> Result<SP1WrapProof<SP1OuterGlobalContext, SP1PcsProofOuter>, TaskError> {
        let execution_record = {
            let mut runtime =
                Executor::<SP1Field, SP1ExtensionField, _>::new(self.program.clone(), inner_perm());
            runtime.witness_stream = self.prover_data.witness_stream(&{
                let SP1RecursionProof { vk, proof, vk_merkle_proof } = shrunk_proof;
                let input =
                    SP1ShapedWitnessValues { vks_and_proofs: vec![(vk, proof)], is_complete: true };
                SP1CircuitWitness::Wrap(
                    self.prover_data
                        .append_merkle_proofs_to_witness(input, vec![vk_merkle_proof.clone()])?,
                )
            })?;
            runtime.run().map_err(|e| TaskError::Fatal(e.into()))?;
            runtime.record
        };

        let (_, proof, _permit) = self
            .prover
            .setup_and_prove_shard(
                self.program.clone(),
                execution_record,
                Some(self.verifying_key.clone()),
                self.permits.clone(),
            )
            .await;

        Ok(SP1WrapProof { vk: self.verifying_key.clone(), proof })
    }

    fn verify(
        &self,
        wrapped_proof: &SP1WrapProof<SP1OuterGlobalContext, SP1PcsProofOuter>,
    ) -> Result<(), TaskError> {
        let SP1WrapProof { vk, proof } = wrapped_proof;
        let mut challenger = SP1OuterGlobalContext::default_challenger();
        vk.observe_into(&mut challenger);
        C::wrap_verifier()
            .verify_shard(vk, proof, &mut challenger)
            .map_err(|e| TaskError::Fatal(e.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp1_core_machine::{riscv::RiscvAir, utils::setup_logger};

    /// Wiring check: the recursion prover stands up all three program families (normalize, plus
    /// within-chunk and across-chunk compose at the binary-tree arities {1, 2}), and the
    /// scope-selector returns the right family. No crypto runs.
    #[tokio::test]
    async fn recursion_prover_builds_three_program_families() {
        use crate::{shapes::create_test_shape, worker::cpu_worker_builder_with_machine};
        use sp1_hypercube::SP1VerifyingKey;
        use sp1_recursion_circuit::dummy::dummy_vk;

        setup_logger();
        let machine = RiscvAir::machine();
        let worker =
            cpu_worker_builder_with_machine(machine.clone()).build().await.expect("worker builds");
        let data = &worker.prover_engine().recursion_prover.prover_data;

        for arity in [1usize, 2] {
            assert!(data.compose_program(ComposeScope::WithinChunk, arity).is_some());
            assert!(data.compose_keys(ComposeScope::WithinChunk, arity).is_some());
            assert!(data.compose_program(ComposeScope::AcrossChunk, arity).is_some());
            assert!(data.compose_keys(ComposeScope::AcrossChunk, arity).is_some());
        }
        assert!(data.compose_program(ComposeScope::WithinChunk, 3).is_none());
        assert!(data.compose_program(ComposeScope::AcrossChunk, 3).is_none());
        assert_eq!(data.within_chunk_compose_programs.len(), 2);
        assert_eq!(data.across_chunk_compose_programs.len(), 2);

        let cluster = machine.shape().chip_clusters.first().expect("machine has a chip cluster");
        let shape = create_test_shape(cluster);
        let program =
            data.normalize.get_program(SP1VerifyingKey { vk: dummy_vk() }, &shape.proof_shapes[0]);
        assert!(program.shape.is_some(), "normalize program is shaped to the reduce shape");
    }

    /// Green harness for iterating on the normalize circuit.
    #[tokio::test]
    #[cfg(feature = "experimental")]
    async fn normalize_produces_a_leaf_proof() {
        use crate::{
            worker::{cpu_worker_builder_with_machine, CommonProverInput},
            CpuSP1ProverComponents,
        };
        use sp1_core_executor::{Program, SP1CoreOpts};
        use sp1_core_machine::{io::SP1Stdin, utils::generate_records};
        use sp1_hypercube::{
            prover::{AirProver, CpuShardProver, ProverSemaphore, SP1InnerPcsProver},
            SP1InnerPcs, SP1VerifyingKey,
        };
        use sp1_prover_types::{
            network_base_types::ProofMode, ArtifactClient, InMemoryArtifactClient,
        };

        setup_logger();
        let machine = RiscvAir::machine();

        // Produce a real single-chunk core shard proof under the chunk's shared commitments.
        let permit = ProverSemaphore::new(1);
        let core_verifier = CpuSP1ProverComponents::core_verifier(machine.clone());
        let prover: CpuShardProver<
            SP1GlobalContext,
            SP1InnerPcs,
            SP1InnerPcsProver,
            RiscvAir<SP1Field>,
        > = CpuShardProver::new(core_verifier.shard_verifier().clone());
        let program = Arc::new(Program::from(&test_artifacts::FIBONACCI_ELF).unwrap());
        let opts = SP1CoreOpts { minimal_trace_chunk_threshold: 1 << 26, ..Default::default() };
        let (records, _) =
            generate_records::<SP1Field>(program.clone(), SP1Stdin::new(), opts, [0; 4]).unwrap();
        let num_shards = records.len() as u32;
        let (pk, vk) = prover.setup(program.clone(), permit.clone()).await;
        let pk = unsafe { pk.into_inner() };
        let mut commitments = Vec::new();
        for record in &records {
            let (proof, _) =
                prover.prove_shard_with_pk(pk.clone(), record.clone(), permit.clone()).await;
            commitments.push(proof.global_commitment.expect("core shard has a global commitment"));
        }
        let mut core_proof = None;
        for record in &records {
            let mut record = record.clone();
            record.set_global_commitments::<SP1GlobalContext>(&commitments);
            let (proof, _) = prover.prove_shard_with_pk(pk.clone(), record, permit.clone()).await;
            core_proof.get_or_insert(proof);
        }
        let core_proof = core_proof.expect("the chunk has at least one shard");

        // Recursion prover with vk verification off (the real vk_map.bin is not yet generated).
        let worker = cpu_worker_builder_with_machine(machine)
            .without_vk_verification()
            .build()
            .await
            .unwrap();
        let rp = &worker.prover_engine().recursion_prover;
        let ids = InMemoryArtifactClient::new();

        let common = CommonProverInput {
            vk: SP1VerifyingKey { vk },
            mode: ProofMode::Compressed,
            deferred_digest: [0; DIGEST_SIZE],
            num_deferred_proofs: 0,
            nonce: [0; 4],
        };
        // The roots are placeholders; the normalize circuit re-derives the shared challenge from the
        // commitments hash and (currently) does not constrain the roots.
        let ctx = ChunkChallengeCtx {
            commitments,
            prev_root: [0; 8],
            cur_root: [0; 8],
            shard_index: 0,
            num_shards,
        };

        // normalize must execute on the shared-FS core proof and yield a leaf.
        rp.normalize(&common, core_proof, &ctx, ids.create_artifact().unwrap())
            .await
            .expect("normalize yields a leaf proof");
    }
}
