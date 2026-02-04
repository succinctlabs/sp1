use std::sync::Arc;

use slop_futures::pipeline::TaskJoinError;
use sp1_hypercube::prover::ProverSemaphore;
use sp1_prover_types::{
    ArtifactClient, ArtifactType, InMemoryArtifactClient, TaskStatus, TaskType,
};
use tokio::{sync::mpsc, task::JoinSet};
use tracing::Instrument;

use crate::{
    worker::{
        node::SP1NodeCore, run_vk_generation, LocalWorkerClient, LocalWorkerClientChannels,
        ProofId, RawTaskRequest, SP1LocalNode, SP1NodeInner, SP1WorkerBuilder, TaskError, TaskId,
        TaskMetadata, WorkerClient,
    },
    SP1ProverComponents,
};

pub struct SP1LocalNodeBuilder<C: SP1ProverComponents> {
    pub worker_builder: SP1WorkerBuilder<C, InMemoryArtifactClient, LocalWorkerClient>,
    pub channels: LocalWorkerClientChannels,
}

impl<C: SP1ProverComponents> Default for SP1LocalNodeBuilder<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: SP1ProverComponents> SP1LocalNodeBuilder<C> {
    /// Creates a new local node builder with a default worker client builder.
    pub fn new() -> Self {
        Self::from_worker_client_builder(SP1WorkerBuilder::new())
    }

    /// Creates a new local node builder from a worker client builder.
    ///
    /// This method can be used to initialize a node from a worker client builder that has already
    /// been configured with the desired prover components.
    pub fn from_worker_client_builder(builder: SP1WorkerBuilder<C>) -> Self {
        let artifact_client = InMemoryArtifactClient::new();
        let (worker_client, channels) = LocalWorkerClient::init();
        let worker_builder =
            builder.with_artifact_client(artifact_client).with_worker_client(worker_client);
        Self { worker_builder, channels }
    }

    /// Sets the core air prover to the worker client builder.
    pub fn with_core_air_prover(
        mut self,
        core_air_prover: Arc<C::CoreProver>,
        permit: ProverSemaphore,
    ) -> Self {
        self.worker_builder = self.worker_builder.with_core_air_prover(core_air_prover, permit);
        self
    }

    /// Sets the compress air prover to the worker client builder.
    pub fn with_compress_air_prover(
        mut self,
        compress_air_prover: Arc<C::RecursionProver>,
        permit: ProverSemaphore,
    ) -> Self {
        self.worker_builder =
            self.worker_builder.with_compress_air_prover(compress_air_prover, permit);
        self
    }

    /// Sets the shrink air prover to the worker client builder.
    pub fn with_shrink_air_prover(
        mut self,
        shrink_air_prover: Arc<C::RecursionProver>,
        permit: ProverSemaphore,
    ) -> Self {
        self.worker_builder = self.worker_builder.with_shrink_air_prover(shrink_air_prover, permit);
        self
    }

    /// Sets the wrap air prover to the worker client builder.
    pub fn with_wrap_air_prover(
        mut self,
        wrap_air_prover: Arc<C::WrapProver>,
        permit: ProverSemaphore,
    ) -> Self {
        self.worker_builder = self.worker_builder.with_wrap_air_prover(wrap_air_prover, permit);
        self
    }

    pub async fn build(self) -> anyhow::Result<SP1LocalNode> {
        // Destructure the builder.
        let Self { worker_builder, mut channels } = self;
        // Get the core options from the worker builder.
        let opts = worker_builder.core_opts().clone();

        // Build the node.
        let worker = worker_builder.build().await?;

        // Create a join set for the task handlers.
        let mut join_set = JoinSet::new();

        // Spawn tasks to handle all the requests. We must spawn a handler for each task type to
        // avoid blocking the main thread by not having processed the input channel.

        // Spawn the controller handler
        join_set.spawn({
            let mut controller_rx = channels.task_receivers.remove(&TaskType::Controller).unwrap();
            let worker = worker.clone();
            async move {
                while let Some((task_id, request)) = controller_rx.recv().await {
                    let span = tracing::debug_span!("Controller", proof_id = %request.context.proof_id, task_id = %task_id);
                    // Run the controller task
                    if let Err(e) = worker.controller().run(request.clone()).instrument(span).await
                    {
                        tracing::error!("Controller: task failed: {e:?}");
                    }

                    // Complete the task
                    if let Err(e) = worker
                        .worker_client()
                        .complete_task(
                            request.context.proof_id,
                            task_id,
                            TaskMetadata { gpu_time: None },
                        )
                        .await
                    {
                        tracing::error!("Controller: marking task as complete failed: {e:?}");
                    }

                    // Remove all the inputs from the task
                    for input in request.inputs {
                        if let Err(e) = worker
                            .artifact_client()
                            .delete(&input, ArtifactType::UnspecifiedArtifactType)
                            .await
                        {
                            tracing::error!("Controller: deleting input artifact failed: {e:?}");
                        }
                    }
                }
            }
        });

        // Spawn the setup handler
        join_set.spawn({
            let mut setup_rx = channels.task_receivers.remove(&TaskType::SetupVkey).unwrap();
            let worker = worker.clone();
            let worker_client = worker.worker_client().clone();
            async move {
                let mut task_set = JoinSet::new();
                let (task_tx, mut task_rx) = mpsc::unbounded_channel();
                loop {
                    tokio::select! {
                        Some((id, request)) = setup_rx.recv() => {
                            let span = tracing::debug_span!("SetupVkey", proof_id = %request.context.proof_id, task_id = %id);
                            let RawTaskRequest { inputs, outputs, context } = request.clone();
                            let proof_id = context.proof_id.clone();
                            let elf = inputs[0].clone();
                            let output = outputs[0].clone();
                            let handle = worker
                                    .prover_engine()
                                    .submit_setup(id.clone(), elf, output)
                                    .instrument(span.clone())
                                    .await
                                    .unwrap();
                            let tx = task_tx.clone();
                            task_set.spawn(async move {
                                let result = handle.await.map(|res| res.map(|(_, metadata)| metadata));
                                TaskOutput::handle_worker_result(result, &tx, proof_id, id, request, TaskType::SetupVkey);
                            }
                          );
                        }

                        Some(output) = task_rx.recv() => {
                            output.handle_task_output(&worker_client).await;
                        }
                        else => {
                            break;
                        }
                    }
                }
            }
        });

        // Spawn the recursion vk tree handler
        join_set.spawn({
            let mut controller_rx =
                channels.task_receivers.remove(&TaskType::UtilVkeyMapController).unwrap();
            let worker = worker.clone();
            async move {
                while let Some((task_id, request)) = controller_rx.recv().await {
                    // Run the controller task
                    if let Err(e) =
                        worker.controller().run_sp1_util_vkey_map_controller(request.clone()).await
                    {
                        tracing::error!("Controller: task failed: {e:?}");
                    }

                    // Complete the task
                    if let Err(e) = worker
                        .worker_client()
                        .complete_task(
                            request.context.proof_id,
                            task_id,
                            TaskMetadata { gpu_time: None },
                        )
                        .await
                    {
                        tracing::error!("Controller: marking task as complete failed: {e:?}");
                    }

                    // Remove all the inputs from the task
                    for input in request.inputs {
                        if let Err(e) = worker
                            .artifact_client()
                            .delete(&input, ArtifactType::UnspecifiedArtifactType)
                            .await
                        {
                            tracing::error!("Controller: deleting input artifact failed: {e:?}");
                        }
                    }
                }
            }
        });

        // Spawn the vk chunk worker handler.
        join_set.spawn({
            let mut core_prover_rx =
                channels.task_receivers.remove(&TaskType::UtilVkeyMapChunk).unwrap();
            let worker = worker.clone();
            let worker_client = worker.worker_client().clone();
            let vk_worker = Arc::new(worker.clone().prover_engine().vk_worker.clone());
            async move {
                let mut task_set = JoinSet::new();
                let (task_tx, mut task_rx) = mpsc::unbounded_channel();

                loop {
                    let vk_worker = vk_worker.clone();
                    tokio::select! {
                        Some((id, request)) = core_prover_rx.recv() => {
                            let proof_id = request.context.proof_id.clone();
                        let handle = run_vk_generation::<_,_>(vk_worker, request, worker.artifact_client().clone());
                            let tx = task_tx.clone();
                            let task_id = id;
                            task_set.spawn(async move {
                                match handle.await {
                                    Ok(()) => {
                                        tx.send((proof_id, task_id, TaskStatus::Succeeded)).ok();
                                    }
                                    Err(e) => {
                                        tracing::error!("Failed to generate vk chunk: {:?}", e);
                                    }
                                }
                            });
                        }

                        Some((proof_id, task_id , status)) = task_rx.recv() => {
                            assert_eq!(status, TaskStatus::Succeeded);
                         if let Err(e) = worker_client.complete_task(proof_id, task_id, TaskMetadata { gpu_time: None }).await {
                             tracing::error!("Failed to complete vk chunk task: {:?}", e);
                         }
                        }
                        else => {
                            break;
                        }
                    }
                }
            }
        });

        // Spawn the prove shard handler
        join_set.spawn({
            let mut core_prover_rx = channels.task_receivers.remove(&TaskType::ProveShard).unwrap();
            let worker = worker.clone();
            let worker_client = worker.worker_client().clone();
            async move {
                let mut task_set = JoinSet::new();
                let (task_tx, mut task_rx) = mpsc::unbounded_channel();

                loop {
                    tokio::select! {
                        Some((id, request)) = core_prover_rx.recv() => {
                            let span = tracing::debug_span!("ProveShard", proof_id = %request.context.proof_id, task_id = %id);
                            let proof_id = request.context.proof_id.clone();
                            let handle = worker
                                .prover_engine()
                                .submit_prove_core_shard(
                                    request.clone(),
                                )
                                .instrument(span.clone())
                                .await
                                .unwrap();
                            let tx = task_tx.clone();
                            task_set.spawn(
                                async move {
                                    let result = handle.await;
                                    TaskOutput::handle_worker_result(result, &tx, proof_id, id, request, TaskType::ProveShard);
                                }.instrument(span)
                           );
                        }

                        Some(output) = task_rx.recv() => {
                            output.handle_task_output(&worker_client).await;
                        }
                        else => {
                            break;
                        }
                    }
                }
            }
        });

        // Spawn the recursion reduce handler
        join_set.spawn({
            let mut recursion_reduce_rx =
                channels.task_receivers.remove(&TaskType::RecursionReduce).unwrap();
            let worker = worker.clone();
            let worker_client = worker.worker_client().clone();
            async move {
                let mut task_set = JoinSet::new();
                let (task_tx, mut task_rx) = mpsc::unbounded_channel();
                loop {
                    tokio::select! {
                        Some((id, request)) = recursion_reduce_rx.recv() => {
                            let span = tracing::debug_span!("RecursionReduce", proof_id = %request.context.proof_id, task_id = %id);
                            let proof_id = request.context.proof_id.clone();
                            let handle = worker
                                .prover_engine()
                                .submit_recursion_reduce(request.clone())
                                .instrument(span.clone())
                                .await
                                .unwrap();
                            let tx = task_tx.clone();
                            task_set.spawn(async move {
                                let result = handle.await;
                                TaskOutput::handle_worker_result(result, &tx, proof_id, id, request, TaskType::RecursionReduce);
                            }.instrument(span)
                          );
                        }

                        Some(output) = task_rx.recv() => {
                            output.handle_task_output(&worker_client).await;
                        }
                        else => {
                            break;
                        }
                    }
                }
            }
        });

        // Spawn the deferred handler
        join_set.spawn({
            let mut recursion_deferred_rx =
                channels.task_receivers.remove(&TaskType::RecursionDeferred).unwrap();
            let worker = worker.clone();
            let worker_client = worker.worker_client().clone();
            async move {
                let mut task_set = JoinSet::new();
                let (task_tx, mut task_rx) = mpsc::unbounded_channel();
                loop {
                    tokio::select! {
                        Some((id, request)) = recursion_deferred_rx.recv() => {
                            let span = tracing::debug_span!("RecursionDeferred", proof_id = %request.context.proof_id, task_id = %id);
                            let proof_id = request.context.proof_id.clone();
                            let handle = worker
                                .prover_engine()
                                .submit_prove_deferred(request.clone())
                                .instrument(span.clone())
                                .await
                                .unwrap();
                            let tx = task_tx.clone();
                            task_set.spawn(async move {
                                let result = handle.await;
                                TaskOutput::handle_worker_result(result, &tx, proof_id, id, request, TaskType::RecursionDeferred);
                            }.instrument(span)
                          );
                        }
                        Some(output) = task_rx.recv() => {
                            output.handle_task_output(&worker_client).await;
                        }
                        else => {
                            break;
                        }
                    }
                }
            }
        });

        // Spawn the deferred marker task handler.
        // Marker deferred tasks are completed by the [TaskType::ProveShard] task, but we still need to consume the receiver here.
        join_set.spawn({
            let mut marker_deferred_task_rx =
                channels.task_receivers.remove(&TaskType::MarkerDeferredRecord).unwrap();
            async move { while let Some((_task_id, _request)) = marker_deferred_task_rx.recv().await {} }
        });

        // Spawn the shrink wrap handler
        //
        // In the local node, we only allow one of these tasks to be run at a time.
        join_set.spawn({
            let mut shrink_wrap_rx = channels.task_receivers.remove(&TaskType::ShrinkWrap).unwrap();
            let worker = worker.clone();
            let worker_client = worker.worker_client().clone();
            async move {
                let (task_tx, mut task_rx) = mpsc::unbounded_channel();
                loop {
                    tokio::select! {
                        Some((id, request)) = shrink_wrap_rx.recv() => {
                            let span = tracing::debug_span!("ShrinkWrap", proof_id = %request.context.proof_id, task_id = %id);
                            let worker = worker.clone();
                            let proof_id = request.context.proof_id.clone();
                            let result = worker
                                .prover_engine()
                                .run_shrink_wrap(request.clone())
                                .instrument(span)
                                .await
                                .map(|_| TaskMetadata::default());
                            TaskOutput::handle_worker_result(Ok(result), &task_tx, proof_id, id, request, TaskType::ShrinkWrap);
                        }
                        Some(output) = task_rx.recv() => {
                            output.handle_task_output(&worker_client).await;
                        }
                        else => {
                            break;
                        }
                    }
                }
            }
        });

        // Spawn the plonk wrap handler
        //
        // in the local node, we only allow one of these tasks to be run at a time.
        join_set.spawn({
            let mut plonk_wrap_rx = channels.task_receivers.remove(&TaskType::PlonkWrap).unwrap();
            let worker = worker.clone();
            let worker_client = worker.worker_client().clone();
            async move {
                let (task_tx, mut task_rx) = mpsc::unbounded_channel();
                loop {
                    tokio::select! {
                        Some((id, request)) = plonk_wrap_rx.recv() => {
                            let span = tracing::debug_span!("PlonkWrap", proof_id = %request.context.proof_id, task_id = %id);
                            let worker = worker.clone();
                            let proof_id = request.context.proof_id.clone();
                            let result = worker
                                .prover_engine()
                                .run_plonk(request.clone())
                                .instrument(span)
                                .await
                                .map(|_| TaskMetadata::default());
                            TaskOutput::handle_worker_result(Ok(result), &task_tx, proof_id, id, request, TaskType::PlonkWrap);
                        }
                        Some(output) = task_rx.recv() => {
                            output.handle_task_output(&worker_client).await;
                        }
                        else => {
                            break;
                        }
                    }
                }
            }
        });

        // Spawn the groth16 wrap handler
        //
        // In the local node, we only allow one of these tasks to be run at a time.
        join_set.spawn({
            let mut groth16_wrap_rx =
                channels.task_receivers.remove(&TaskType::Groth16Wrap).unwrap();
            let worker = worker.clone();
            async move {
                let (task_tx, mut task_rx) = mpsc::unbounded_channel();
                loop {
                    tokio::select! {
                        Some((id, request)) = groth16_wrap_rx.recv() => {
                            let span = tracing::debug_span!("Groth16Wrap", proof_id = %request.context.proof_id, task_id = %id);
                            let worker = worker.clone();
                            let proof_id = request.context.proof_id.clone();
                            let result = worker
                                .prover_engine()
                                .run_groth16(request.clone())
                                .instrument(span)
                                .await
                                .map(|_| TaskMetadata::default());
                            TaskOutput::handle_worker_result(Ok(result), &task_tx, proof_id, id, request, TaskType::Groth16Wrap);
                        }
                        Some(output) = task_rx.recv() => {
                            output.handle_task_output(worker.worker_client()).await;
                        }
                        else => {
                            break;
                        }
                    }
                }
            }
        });

        // Get the verifier, artifact client, and worker client from the worker
        let verifier = worker.verifier().clone();
        let artifact_client = worker.artifact_client().clone();
        let worker_client = worker.worker_client().clone();
        let core = SP1NodeCore::new(verifier, opts);
        let inner =
            Arc::new(SP1NodeInner { artifact_client, worker_client, core, _tasks: join_set });
        Ok(SP1LocalNode { inner })
    }
}

struct TaskOutput {
    proof_id: ProofId,
    task_id: TaskId,
    status: TaskStatus,
    task_metadata: TaskMetadata,
    task_data: Option<RawTaskRequest>,
    task_type: TaskType,
}

impl TaskOutput {
    fn handle_worker_result(
        result: Result<Result<TaskMetadata, TaskError>, TaskJoinError>,
        tx: &mpsc::UnboundedSender<TaskOutput>,
        proof_id: ProofId,
        task_id: TaskId,
        request: RawTaskRequest,
        task_type: TaskType,
    ) {
        match result {
            Ok(Ok(task_metadata)) => {
                tracing::debug!("task succeeded");
                let task_output = TaskOutput {
                    proof_id,
                    task_id,
                    status: TaskStatus::Succeeded,
                    task_metadata,
                    task_data: None,
                    task_type,
                };
                tx.send(task_output).ok();
            }
            Ok(Err(TaskError::Retryable(e))) => {
                tracing::error!("task failed with retryable error: {:?}", e);
                let task_output = TaskOutput {
                    proof_id,
                    task_id,
                    status: TaskStatus::FailedRetryable,
                    task_metadata: TaskMetadata::default(),
                    task_data: Some(request),
                    task_type,
                };
                tx.send(task_output).ok();
            }
            Ok(Err(TaskError::Fatal(e))) => {
                tracing::error!("task failed with fatal error: {:?}", e);
                let task_output = TaskOutput {
                    proof_id,
                    task_id,
                    status: TaskStatus::FailedFatal,
                    task_metadata: TaskMetadata::default(),
                    task_data: None,
                    task_type,
                };
                tx.send(task_output).ok();
            }
            Ok(Err(TaskError::Execution(e))) => {
                tracing::error!("task failed with fatal error: {:?}", e);
                let task_output = TaskOutput {
                    proof_id,
                    task_id,
                    status: TaskStatus::FailedFatal,
                    task_metadata: TaskMetadata::default(),
                    task_data: None,
                    task_type,
                };
                tx.send(task_output).ok();
            }
            Err(e) => {
                tracing::error!("task panicked: {:?}", e);
            }
        }
    }

    async fn handle_task_output(self, worker_client: &LocalWorkerClient) {
        let TaskOutput { proof_id, task_id, status, task_metadata, task_data, task_type } = self;
        match status {
            TaskStatus::Succeeded => {
                let result = worker_client
                    .complete_task(proof_id.clone(), task_id.clone(), task_metadata)
                    .await;
                if let Err(e) = result {
                    tracing::error!(
                        "Failed to complete task, proof_id: {:?}, task_id: {:?}, error: {:?}",
                        proof_id,
                        task_id,
                        e
                    );
                }
            }
            TaskStatus::FailedRetryable => {
                let task = task_data.unwrap();
                let res = worker_client.submit_task(task_type, task).await;
                if let Err(e) = res {
                    tracing::error!("Failed to submit retry, task: {:?}, error: {:?}", task_id, e);
                }
            }
            TaskStatus::FailedFatal => {
                let res = worker_client
                    .update_task_status(task_id.clone(), TaskStatus::FailedFatal)
                    .await;
                if let Err(e) = res {
                    tracing::error!("Failed to fail task, task: {:?}, error: {:?}", task_id, e);
                }
            }
            _ => {}
        }
    }
}
