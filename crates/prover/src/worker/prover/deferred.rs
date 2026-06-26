use std::sync::Arc;

use slop_algebra::AbstractField;
use slop_futures::pipeline::{AsyncEngine, AsyncWorker, Pipeline, SubmitHandle};

use sp1_hypercube::HashableKey;
use sp1_primitives::SP1Field;
use sp1_prover_types::{Artifact, ArtifactClient};
use sp1_recursion_circuit::machine::SP1DeferredWitnessValues;

use crate::{
    worker::{
        CommonProverInput, ProverMetrics, RawTaskRequest, SP1DeferredData, SP1RecursionProver,
        TaskContext, TaskError, TaskMetadata,
    },
    SP1CircuitWitness, SP1ProverComponents,
};

#[derive(Clone)]
pub struct SP1DeferredProverConfig {
    /// The number of deferred workers.
    pub num_deferred_workers: usize,
    /// The buffer size for the deferred workers.
    pub deferred_buffer_size: usize,
}

pub type SP1DeferredEngine<A, C> = AsyncEngine<
    RecursionDeferredTaskRequest,
    Result<TaskMetadata, TaskError>,
    SP1DeferredWorker<A, C>,
>;

pub type SP1DeferredSubmitHandle<A, C> = SubmitHandle<SP1DeferredEngine<A, C>>;

pub struct SP1DeferredProver<A, C: SP1ProverComponents> {
    engine: Arc<SP1DeferredEngine<A, C>>,
}

impl<A, C: SP1ProverComponents> Clone for SP1DeferredProver<A, C> {
    fn clone(&self) -> Self {
        Self { engine: self.engine.clone() }
    }
}

impl<A: ArtifactClient, C: SP1ProverComponents> SP1DeferredProver<A, C> {
    pub fn new(
        config: SP1DeferredProverConfig,
        recursion_prover: SP1RecursionProver<A, C>,
        artifact_client: A,
    ) -> Self {
        let deferred_workers = (0..config.num_deferred_workers)
            .map(|_| SP1DeferredWorker {
                recursion_prover: recursion_prover.clone(),
                artifact_client: artifact_client.clone(),
            })
            .collect();
        let engine = AsyncEngine::new(deferred_workers, config.deferred_buffer_size);
        Self { engine: Arc::new(engine) }
    }

    pub(super) async fn submit(
        &self,
        task: RawTaskRequest,
    ) -> Result<SP1DeferredSubmitHandle<A, C>, TaskError> {
        let task = RecursionDeferredTaskRequest::from_raw(task)?;
        let handle = self.engine.submit(task).await?;
        Ok(handle)
    }
}

pub struct SP1DeferredWorker<A, C: SP1ProverComponents> {
    recursion_prover: SP1RecursionProver<A, C>,
    artifact_client: A,
}

pub struct RecursionDeferredTaskRequest {
    /// The common input artifact.
    pub common_input: Artifact,
    /// The deferred data artifact.
    pub deferred_data: Artifact,
    // The output artifact.
    pub output: Artifact,
    /// The task context.
    pub context: TaskContext,
}

impl RecursionDeferredTaskRequest {
    pub fn from_raw(request: RawTaskRequest) -> Result<Self, TaskError> {
        let RawTaskRequest { inputs, mut outputs, context } = request;
        let [common_input, deferred_data] = inputs
            .try_into()
            .map_err(|_| TaskError::Fatal(anyhow::anyhow!("Invalid input length")))?;
        let output =
            outputs.pop().ok_or(TaskError::Fatal(anyhow::anyhow!("No output artifact")))?;

        Ok(RecursionDeferredTaskRequest { common_input, deferred_data, output, context })
    }

    pub fn into_raw(self) -> Result<RawTaskRequest, TaskError> {
        let RecursionDeferredTaskRequest { common_input, deferred_data, output, context } = self;

        let inputs = vec![common_input, deferred_data];
        let raw_task_request = RawTaskRequest { inputs, outputs: vec![output], context };
        Ok(raw_task_request)
    }
}

impl<A: ArtifactClient, C: SP1ProverComponents>
    AsyncWorker<RecursionDeferredTaskRequest, Result<TaskMetadata, TaskError>>
    for SP1DeferredWorker<A, C>
{
    async fn call(&self, input: RecursionDeferredTaskRequest) -> Result<TaskMetadata, TaskError> {
        let RecursionDeferredTaskRequest { common_input, deferred_data, output, .. } = input;

        // Download the inputs
        let (common_input, deferred_data) = tokio::try_join!(
            self.artifact_client.download::<CommonProverInput>(&common_input),
            self.artifact_client.download::<SP1DeferredData>(&deferred_data),
        )?;

        let SP1DeferredData {
            input,
            start_reconstruct_deferred_digest,
            deferred_proof_index,
            vk_merkle_proofs,
        } = deferred_data;

        let input = self
            .recursion_prover
            .prover_data
            .append_merkle_proofs_to_witness(input, vk_merkle_proofs)?;

        let nonce = common_input.nonce.map(SP1Field::from_canonical_u32);

        let witness = SP1DeferredWitnessValues {
            vks_and_proofs: input.compress_val.vks_and_proofs,
            vk_merkle_data: input.merkle_val,
            start_reconstruct_deferred_digest,
            sp1_vk_digest: common_input.vk.hash_koalabear(),
            end_pc: common_input.vk.vk.pc_start,
            initial_memory_root: common_input.vk.vk.initial_memory_root,
            proof_nonce: nonce,
            deferred_proof_index,
        };

        let witness = SP1CircuitWitness::Deferred(witness);

        let program = self.recursion_prover.prover_data.deferred_program().clone();

        // Get the deferred proof
        let metrics = ProverMetrics::new();
        let metadata = self
            .recursion_prover
            .submit_prove_shard(program, witness, output, metrics)
            .await?
            .await
            .map_err(|e| TaskError::Fatal(e.into()))??;

        Ok(metadata)
    }
}
