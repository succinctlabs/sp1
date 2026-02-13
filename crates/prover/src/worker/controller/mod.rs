mod compress;
mod core;
mod deferred;
mod global;
mod precompiles;
mod splicing;
mod vk_tree;

pub use compress::*;
pub use core::*;
pub use deferred::*;
pub use global::*;
pub use precompiles::*;
pub use splicing::*;
pub use vk_tree::*;

use lru::LruCache;

use slop_algebra::PrimeField32;

use sp1_core_executor::{MinimalExecutor, SP1CoreOpts};
use sp1_core_machine::{executor::ExecutionOutput, io::SP1Stdin};
use sp1_hypercube::{
    air::{PublicValues, PROOF_NONCE_NUM_WORDS},
    SP1PcsProofInner, SP1VerifyingKey, ShardProof,
};
use sp1_primitives::{io::SP1PublicValues, SP1GlobalContext};
use sp1_prover_types::{
    network_base_types::ProofMode, Artifact, ArtifactClient, ArtifactType, TaskStatus, TaskType,
};
use sp1_verifier::{ProofFromNetwork, SP1Proof};
use std::{borrow::Borrow, sync::Arc};
use tokio::{
    sync::{mpsc, oneshot, Mutex, MutexGuard},
    task::JoinSet,
};
use tracing::Instrument;

use crate::{
    verify::SP1Verifier,
    worker::{RawTaskRequest, TaskContext, TaskError, WorkerClient},
    SP1_CIRCUIT_VERSION,
};

#[derive(Clone)]
pub struct MinimalExecutorCache(Arc<Mutex<Option<MinimalExecutor>>>);

impl MinimalExecutorCache {
    pub fn empty() -> Self {
        Self(Arc::new(Mutex::new(None)))
    }

    pub async fn lock(&self) -> MutexGuard<'_, Option<MinimalExecutor>> {
        self.0.lock().await
    }
}

#[derive(Clone)]
pub struct SP1ControllerConfig {
    pub opts: SP1CoreOpts,
    pub num_splicing_workers: usize,
    pub splicing_buffer_size: usize,
    pub max_reduce_arity: usize,
    pub number_of_send_splice_workers_per_splice: usize,
    pub send_splice_input_buffer_size_per_splice: usize,
    pub use_fixed_pk: bool,
    pub global_memory_buffer_size: usize,
}

pub struct SP1Controller<A, W> {
    config: SP1ControllerConfig,
    setup_cache: Arc<Mutex<LruCache<Artifact, SP1VerifyingKey>>>,
    pub(crate) artifact_client: A,
    pub(crate) worker_client: W,
    pub(crate) verifier: SP1Verifier,
    minimal_executor_cache: Option<MinimalExecutorCache>,
}

impl<A, W> SP1Controller<A, W>
where
    A: ArtifactClient,
    W: WorkerClient,
{
    pub fn new(
        config: SP1ControllerConfig,
        artifact_client: A,
        worker_client: W,
        verifier: SP1Verifier,
    ) -> Self {
        let minimal_executor_cache =
            if config.use_fixed_pk { Some(MinimalExecutorCache::empty()) } else { None };

        Self {
            config,
            setup_cache: Arc::new(Mutex::new(LruCache::new(20.try_into().unwrap()))),
            artifact_client,
            worker_client,
            verifier,
            minimal_executor_cache,
        }
    }

    #[inline]
    pub const fn opts(&self) -> &SP1CoreOpts {
        &self.config.opts
    }

    #[inline]
    pub const fn max_reduce_arity(&self) -> usize {
        self.config.max_reduce_arity
    }

    #[inline]
    pub const fn global_memory_buffer_size(&self) -> usize {
        self.config.global_memory_buffer_size
    }

    pub fn initialize_splicing_engine(&self) -> Arc<SplicingEngine<A, W>> {
        let splicing_workers = (0..self.config.num_splicing_workers)
            .map(|_| {
                SplicingWorker::new(
                    self.artifact_client.clone(),
                    self.worker_client.clone(),
                    self.config.number_of_send_splice_workers_per_splice,
                    self.config.send_splice_input_buffer_size_per_splice,
                )
            })
            .collect();
        Arc::new(SplicingEngine::new(splicing_workers, self.config.splicing_buffer_size))
    }

    pub async fn run(&self, request: RawTaskRequest) -> Result<ExecutionOutput, TaskError> {
        let RawTaskRequest { inputs, outputs, context } = request;
        let elf = inputs[0].clone();
        let stdin_artifact = inputs[1].clone();
        let mode_artifact = inputs[2].clone();
        let cycle_limit = inputs.get(3).and_then(|a| a.clone().to_id().parse::<u64>().ok());
        let proof_nonce = inputs.get(4);
        let [output] = outputs.try_into().unwrap();
        let mode = {
            let parsed =
                mode_artifact.to_id().parse::<i32>().map_err(|e| TaskError::Fatal(e.into()))?;
            ProofMode::try_from(parsed).map_err(|e| TaskError::Fatal(e.into()))?
        };

        let stdin_download_handle =
            self.artifact_client.download_stdin::<SP1Stdin>(&stdin_artifact);

        let proof_nonce = match proof_nonce {
            Some(artifact) => {
                self.artifact_client.download::<[u32; PROOF_NONCE_NUM_WORDS]>(artifact).await?
            }
            None => [0u32; PROOF_NONCE_NUM_WORDS],
        };

        let vkey_download_handle = tokio::spawn({
            let artifact_client_clone = self.artifact_client.clone();
            let worker_client_clone = self.worker_client.clone();
            let elf_clone = elf.clone();
            let setup_cache = self.setup_cache.clone();
            let context = context.clone();
            async move {
                let mut lock = setup_cache.lock().await;
                let vkey = lock.get(&elf_clone).cloned();
                drop(lock);
                let vk = if let Some(vkey) = vkey {
                    tracing::debug!("setup cache hit");
                    vkey.clone()
                } else {
                    // Create a setup task and wait for the vk
                    let vk_artifact = artifact_client_clone.create_artifact()?;
                    let setup_request = RawTaskRequest {
                        inputs: vec![elf_clone.clone()],
                        outputs: vec![vk_artifact.clone()],
                        context: context.clone(),
                    };

                    tracing::debug!("submitting setup task");
                    let setup_id =
                        worker_client_clone.submit_task(TaskType::SetupVkey, setup_request).await?;

                    // Wait for the setup task to finish
                    let subscriber =
                        worker_client_clone.subscriber(context.proof_id.clone()).await?.per_task();
                    let status = subscriber
                        .wait_task(setup_id)
                        .instrument(tracing::debug_span!("setup task"))
                        .await
                        .map_err(|e| TaskError::Fatal(e.into()))?;
                    if status != TaskStatus::Succeeded {
                        return Err(TaskError::Fatal(anyhow::anyhow!("setup task failed")));
                    }
                    tracing::debug!("setup task succeeded");
                    let vk =
                        artifact_client_clone.download::<SP1VerifyingKey>(&vk_artifact).await?;
                    setup_cache.lock().await.put(elf_clone, vk.clone());
                    vk
                };
                Ok(vk)
            }
            .instrument(tracing::debug_span!("setup vkey"))
        });

        let stdin: SP1Stdin = stdin_download_handle.await?;
        let vk = vkey_download_handle.await.map_err(|e| TaskError::Fatal(e.into()))??;

        let stdin = Arc::new(stdin);

        let deferred_proofs = stdin.proofs.iter().map(|(proof, _)| proof.clone());
        let deferred_inputs = DeferredInputs::new(deferred_proofs);

        let num_deferred_proofs = deferred_inputs.num_deferred_proofs();
        let deferred_digest = deferred_inputs.deferred_digest().map(|x| x.as_canonical_u32());
        // Create the common input
        let common_input = CommonProverInput {
            vk,
            mode,
            deferred_digest,
            num_deferred_proofs,
            nonce: proof_nonce,
        };
        // Upload the common input
        let common_input_artifact = self.artifact_client.create_artifact()?;
        self.artifact_client.upload(&common_input_artifact.clone(), common_input.clone()).await?;

        let (core_proof_tx, core_proof_rx) = mpsc::unbounded_channel();

        let splicing_engine = self.initialize_splicing_engine();
        let executor = SP1CoreExecutor::new(
            splicing_engine,
            self.global_memory_buffer_size(),
            elf,
            stdin.clone(),
            common_input_artifact.clone(),
            self.opts().clone(),
            num_deferred_proofs,
            context.clone(),
            core_proof_tx.clone(),
            self.artifact_client.clone(),
            self.worker_client.clone(),
            self.minimal_executor_cache.clone(),
            cycle_limit,
        );
        let mut join_set = JoinSet::<Result<(), TaskError>>::new();

        let mut core_proof_artifact = None;
        let mut compress_proof_artifact = None;
        let mut shrinkwrap_proof_artifact = None;
        let mut groth16_proof_artifact = None;
        let mut plonk_proof_artifact = None;

        let (compress_complete_tx, compress_complete_rx) = tokio::sync::oneshot::channel();

        if mode == ProofMode::Core {
            core_proof_artifact = Some(self.artifact_client.create_artifact()?);
            join_set.spawn(collect_core_proofs(
                self.worker_client.clone(),
                self.artifact_client.clone(),
                core_proof_artifact.clone().unwrap(),
                context.clone(),
                core_proof_rx,
            ));
        } else {
            let mut tree = CompressTree::new(self.max_reduce_arity());
            let artifact_client = self.artifact_client.clone();
            let worker_client = self.worker_client.clone();
            let context = context.clone();
            compress_proof_artifact = Some(self.artifact_client.create_artifact()?);
            let compress_proof_artifact = compress_proof_artifact.clone().unwrap();
            join_set.spawn(
                async move {
                    tree.reduce_proofs(
                        context,
                        compress_proof_artifact.clone(),
                        core_proof_rx,
                        &artifact_client,
                        &worker_client,
                    )
                    .await?;
                    compress_complete_tx.send(()).unwrap();
                    Ok(())
                }
                .instrument(tracing::debug_span!("reduce")),
            );
        }

        match mode {
            ProofMode::Groth16 => {
                shrinkwrap_proof_artifact = Some(self.artifact_client.create_artifact()?);
                groth16_proof_artifact = Some(self.artifact_client.create_artifact()?);

                let shrinkwrap_task = RawTaskRequest {
                    inputs: vec![compress_proof_artifact.clone().unwrap()],
                    outputs: vec![shrinkwrap_proof_artifact.clone().unwrap()],
                    context: context.clone(),
                };

                let groth16_task = RawTaskRequest {
                    inputs: vec![shrinkwrap_proof_artifact.clone().unwrap()],
                    outputs: vec![groth16_proof_artifact.clone().unwrap()],
                    context: context.clone(),
                };

                let subscriber =
                    self.worker_client.subscriber(context.proof_id.clone()).await?.per_task();
                let worker_client = self.worker_client.clone();
                join_set.spawn(async move {
                    compress_complete_rx.await.unwrap();

                    let shrinkwrap_task_id =
                        worker_client.submit_task(TaskType::ShrinkWrap, shrinkwrap_task).await?;
                    subscriber.wait_task(shrinkwrap_task_id).await?;

                    let groth16_task_id =
                        worker_client.submit_task(TaskType::Groth16Wrap, groth16_task).await?;
                    subscriber.wait_task(groth16_task_id).await?;
                    Ok(())
                });
            }
            ProofMode::Plonk => {
                shrinkwrap_proof_artifact = Some(self.artifact_client.create_artifact()?);
                plonk_proof_artifact = Some(self.artifact_client.create_artifact()?);

                let shrinkwrap_task = RawTaskRequest {
                    inputs: vec![compress_proof_artifact.clone().unwrap()],
                    outputs: vec![shrinkwrap_proof_artifact.clone().unwrap()],
                    context: context.clone(),
                };
                let plonk_task = RawTaskRequest {
                    inputs: vec![shrinkwrap_proof_artifact.clone().unwrap()],
                    outputs: vec![plonk_proof_artifact.clone().unwrap()],
                    context: context.clone(),
                };

                let subscriber =
                    self.worker_client.subscriber(context.proof_id.clone()).await?.per_task();
                let worker_client = self.worker_client.clone();
                join_set.spawn(async move {
                    compress_complete_rx.await.unwrap();

                    let shrinkwrap_task_id =
                        worker_client.submit_task(TaskType::ShrinkWrap, shrinkwrap_task).await?;
                    subscriber.wait_task(shrinkwrap_task_id).await?;

                    let plonk_task_id =
                        worker_client.submit_task(TaskType::PlonkWrap, plonk_task).await?;
                    subscriber.wait_task(plonk_task_id).await?;
                    Ok(())
                });
            }
            _ => {}
        }

        // Spawn a task to spawn the deferred tasks
        join_set.spawn(deferred_inputs.emit_deferred_tasks(
            common_input_artifact.clone(),
            context.clone(),
            core_proof_tx,
            self.artifact_client.clone(),
            self.worker_client.clone(),
        ));

        // Spawn a task for the executor and get a result handle rx.
        let (executor_result_tx, executor_result_rx) = oneshot::channel();
        join_set.spawn(
            async move {
                let result = executor.execute().await?;
                tracing::trace!("executor finished");
                executor_result_tx
                    .send(result)
                    .map_err(|_| TaskError::Fatal(anyhow::anyhow!("Controller panicked")))?;
                Ok(())
            }
            .instrument(tracing::debug_span!("execute")),
        );

        // Wait for the executor and proof tasks to finish
        while let Some(result) = join_set.join_next().await {
            result.map_err(|e| TaskError::Fatal(e.into()))??;
        }

        // Get the proof and wrap it if the mode is either groth16 or plonk.
        let inner_proof = match mode {
            ProofMode::Core => {
                let shard_proofs =
                    self.artifact_client.download(&core_proof_artifact.clone().unwrap()).await?;
                SP1Proof::Core(shard_proofs)
            }
            ProofMode::Compressed => {
                let proof = self
                    .artifact_client
                    .download(&compress_proof_artifact.clone().unwrap())
                    .await?;
                SP1Proof::Compressed(Box::new(proof))
            }
            ProofMode::Plonk => {
                let proof =
                    self.artifact_client.download(&plonk_proof_artifact.clone().unwrap()).await?;
                SP1Proof::Plonk(proof)
            }
            ProofMode::Groth16 => {
                let proof =
                    self.artifact_client.download(&groth16_proof_artifact.clone().unwrap()).await?;
                SP1Proof::Groth16(proof)
            }
            _ => unimplemented!("proof mode not supported: {:?}", mode),
        };

        let result = executor_result_rx
            .await
            .map_err(|_| TaskError::Fatal(anyhow::anyhow!("Executor panicked")))?;

        // Check if cycle limit was exceeded.
        if let Some(limit) = cycle_limit {
            if limit > 0 && result.cycles > limit {
                return Err(TaskError::Fatal(anyhow::anyhow!(
                    "cycle limit exceeded: {} > {}",
                    result.cycles,
                    limit
                )));
            }
        }

        // Pair with public values and version
        let public_values = SP1PublicValues::from(&result.public_value_stream);
        let proof = ProofFromNetwork {
            proof: inner_proof,
            public_values,
            sp1_version: SP1_CIRCUIT_VERSION.to_string(),
        };

        // Upload the proof
        self.artifact_client.upload_proof(&output, proof).await?;

        // Clean up artifacts
        let artifacts_to_cleanup = vec![
            Some(common_input_artifact),
            Some(stdin_artifact),
            core_proof_artifact,
            compress_proof_artifact,
            shrinkwrap_proof_artifact,
            groth16_proof_artifact,
            plonk_proof_artifact,
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

        self.artifact_client
            .delete_batch(&artifacts_to_cleanup, ArtifactType::UnspecifiedArtifactType)
            .await?;

        Ok(result)
    }
}

async fn collect_core_proofs(
    worker_client: impl WorkerClient,
    artifact_client: impl ArtifactClient,
    result_artifact: Artifact,
    context: TaskContext,
    mut core_proof_rx: mpsc::UnboundedReceiver<ProofData>,
) -> Result<(), TaskError> {
    let subscriber = worker_client.subscriber(context.proof_id.clone()).await?.per_task();
    let mut shard_proofs = Vec::new();
    while let Some(proof_data) = core_proof_rx.recv().await {
        let ProofData { task_id, proof, .. } = proof_data;
        // Wait for the task to finish
        let status = subscriber.wait_task(task_id.clone()).await?;
        if status != TaskStatus::Succeeded {
            tracing::error!("core proof task failed: {:?}", task_id);
            return Err(TaskError::Fatal(anyhow::anyhow!("core proof task failed: {:?}", task_id)));
        }
        // Download the proof
        let proof = artifact_client
            .download::<ShardProof<SP1GlobalContext, SP1PcsProofInner>>(&proof)
            .await?;
        shard_proofs.push(proof);
    }
    shard_proofs.sort_by_key(|shard_proof| {
        let public_values: &PublicValues<[_; 4], [_; 3], [_; 4], _> =
            shard_proof.public_values.as_slice().borrow();
        public_values.range()
    });

    // Upload the collected shard proofs
    artifact_client.upload(&result_artifact, shard_proofs).await?;

    Ok(())
}
