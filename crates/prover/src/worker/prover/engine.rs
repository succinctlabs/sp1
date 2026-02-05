use std::sync::Arc;

use slop_futures::pipeline::SubmitError;
use sp1_core_executor::SP1CoreOpts;
use sp1_hypercube::prover::ProverSemaphore;
use sp1_prover_types::{Artifact, ArtifactClient};

use crate::{
    worker::{
        CoreProveSubmitHandle, RawTaskRequest, RecursionVkWorker, ReduceSubmitHandle,
        SP1CoreProver, SP1CoreProverConfig, SP1DeferredProver, SP1DeferredProverConfig,
        SP1DeferredSubmitHandle, SP1RecursionProver, SP1RecursionProverConfig, SetupSubmitHandle,
        SetupTask, TaskError, TaskId, WorkerClient,
    },
    SP1ProverComponents, WrapProverBuilder,
};

#[derive(Clone)]
pub struct SP1ProverConfig {
    pub core_prover_config: SP1CoreProverConfig,
    pub recursion_prover_config: SP1RecursionProverConfig,
    pub deferred_prover_config: SP1DeferredProverConfig,
}

pub struct SP1ProverEngine<A, W, C: SP1ProverComponents> {
    pub core_prover: SP1CoreProver<A, W, C>,
    pub recursion_prover: SP1RecursionProver<A, C>,
    pub deferred_prover: SP1DeferredProver<A, C>,
    pub vk_worker: RecursionVkWorker<C>,
}

pub struct WrapAirProverInit<C: SP1ProverComponents> {
    builder: Arc<C::WrapProverBuilder>,
    permits: ProverSemaphore,
}

impl<C: SP1ProverComponents> WrapAirProverInit<C> {
    pub(crate) fn new(builder: C::WrapProverBuilder, permits: ProverSemaphore) -> Self {
        Self { builder: Arc::new(builder), permits }
    }

    pub(crate) fn permits(&self) -> ProverSemaphore {
        self.permits.clone()
    }

    pub(crate) fn build(&self) -> Arc<C::WrapProver> {
        self.builder.build()
    }
}

impl<A: ArtifactClient, W: WorkerClient, C: SP1ProverComponents> SP1ProverEngine<A, W, C> {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        config: SP1ProverConfig,
        opts: SP1CoreOpts,
        artifact_client: A,
        worker_client: W,
        core_prover_and_permits: (Arc<C::CoreProver>, ProverSemaphore),
        recursion_prover_and_permits: (Arc<C::RecursionProver>, ProverSemaphore),
        shrink_air_prover_and_permits: (Arc<C::RecursionProver>, ProverSemaphore),
        wrap_air_prover_init: WrapAirProverInit<C>,
    ) -> Self {
        let recursion_prover = SP1RecursionProver::new(
            config.recursion_prover_config,
            artifact_client.clone(),
            recursion_prover_and_permits.clone(),
            shrink_air_prover_and_permits,
            wrap_air_prover_init,
        )
        .await;

        let core_prover = SP1CoreProver::new(
            config.core_prover_config,
            opts,
            artifact_client.clone(),
            worker_client,
            core_prover_and_permits.0,
            core_prover_and_permits.1,
            recursion_prover.clone(),
        );

        let deferred_prover = SP1DeferredProver::new(
            config.deferred_prover_config,
            recursion_prover.clone(),
            artifact_client,
        );

        let vk_worker = RecursionVkWorker {
            recursion_permits: recursion_prover_and_permits.1,
            recursion_prover: recursion_prover_and_permits.0,
            shrink_prover: recursion_prover.shrink_prover.clone(),
        };

        Self { core_prover, vk_worker, recursion_prover, deferred_prover }
    }

    pub async fn submit_prove_core_shard(
        &self,
        request: RawTaskRequest,
    ) -> Result<CoreProveSubmitHandle<A, W, C>, TaskError> {
        self.core_prover.submit_prove_shard(request).await
    }

    pub async fn submit_setup(
        &self,
        id: TaskId,
        elf: Artifact,
        output: Artifact,
    ) -> Result<SetupSubmitHandle<A, C>, SubmitError> {
        let handle = self.core_prover.submit_setup(SetupTask { id, elf, output }).await?;
        Ok(handle)
    }

    pub async fn submit_recursion_reduce(
        &self,
        request: RawTaskRequest,
    ) -> Result<ReduceSubmitHandle<A, C>, TaskError> {
        self.recursion_prover.submit_recursion_reduce(request).await
    }

    pub async fn submit_prove_deferred(
        &self,
        request: RawTaskRequest,
    ) -> Result<SP1DeferredSubmitHandle<A, C>, TaskError> {
        self.deferred_prover.submit(request).await
    }

    pub async fn run_shrink_wrap(&self, request: RawTaskRequest) -> Result<(), TaskError> {
        self.recursion_prover.run_shrink_wrap(request).await
    }

    pub async fn run_plonk(&self, request: RawTaskRequest) -> Result<(), TaskError> {
        self.recursion_prover.run_plonk(request).await
    }

    pub async fn run_groth16(&self, request: RawTaskRequest) -> Result<(), TaskError> {
        self.recursion_prover.run_groth16(request).await
    }
}
