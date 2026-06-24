use std::sync::Arc;

use slop_futures::pipeline::{AsyncEngine, AsyncWorker, Pipeline, SubmitError, SubmitHandle};
use sp1_core_executor::{Program, SP1CoreOpts};
use sp1_core_machine::riscv::RiscvAir;
use sp1_hypercube::{
    prover::{CoreProofShape, ProverSemaphore, ProvingKey},
    InnerSC, Machine, MachineVerifier, SP1PcsProofInner, SP1VerifyingKey, ShardProof,
};
use sp1_primitives::{SP1Field, SP1GlobalContext};
use sp1_prover_types::{Artifact, ArtifactClient};
use sp1_recursion_circuit::shard::RecursiveShardVerifier;
use sp1_recursion_compiler::{circuit::AsmConfig, config::InnerConfig};
use sp1_recursion_executor::RecursionProgram;
use tokio::sync::OnceCell;

use crate::{
    components::CoreSC,
    recursion::normalize_program_from_input,
    shapes::{SP1NormalizeCache, SP1NormalizeInputShape, SP1RecursionProofShape},
    worker::{AirProverWorker, TaskError, TaskId, TaskMetadata},
    SP1ProverComponents,
};

pub struct SetupTask {
    pub id: TaskId,
    pub elf: Artifact,
    pub output: Artifact,
}

/// Builds (and caches) the `normalize` program for a core shard proof's shape.
pub struct NormalizeProgramCompiler {
    cache: SP1NormalizeCache,
    recursive_verifier: RecursiveShardVerifier<SP1GlobalContext, RiscvAir<SP1Field>, InnerConfig>,
    reduce_shape: SP1RecursionProofShape,
    verifier: MachineVerifier<SP1GlobalContext, CoreSC>,
}

impl NormalizeProgramCompiler {
    pub fn new(
        cache: SP1NormalizeCache,
        recursive_verifier: RecursiveShardVerifier<
            SP1GlobalContext,
            RiscvAir<SP1Field>,
            InnerConfig,
        >,

        reduce_shape: SP1RecursionProofShape,
        machine_verifier: MachineVerifier<SP1GlobalContext, CoreSC>,
    ) -> Self {
        Self { cache, recursive_verifier, reduce_shape, verifier: machine_verifier }
    }

    pub fn machine(&self) -> &Machine<SP1Field, RiscvAir<SP1Field>> {
        self.verifier.machine()
    }

    pub fn get_program(
        &self,
        vk: SP1VerifyingKey,
        proof_shape: &CoreProofShape<SP1Field, RiscvAir<SP1Field>>,
    ) -> Arc<RecursionProgram<SP1Field>> {
        get_normalize_program(
            vk,
            &self.verifier,
            &self.recursive_verifier,
            proof_shape,
            &self.reduce_shape,
            Some(&self.cache),
        )
    }

    /// Build (or fetch from cache) the normalize program for a concrete core shard proof, deriving
    /// the proof's shape from the proof itself.
    pub fn program_for_proof(
        &self,
        vk: SP1VerifyingKey,
        proof: &ShardProof<SP1GlobalContext, SP1PcsProofInner>,
    ) -> Arc<RecursionProgram<SP1Field>> {
        let proof_shape = self.verifier.shape_from_proof(proof);
        self.get_program(vk, &proof_shape)
    }
}

pub fn get_normalize_program(
    vk: SP1VerifyingKey,
    verifier: &MachineVerifier<SP1GlobalContext, InnerSC<RiscvAir<SP1Field>>>,
    recursive_verifier: &RecursiveShardVerifier<SP1GlobalContext, RiscvAir<SP1Field>, AsmConfig>,
    proof_shape: &CoreProofShape<SP1Field, RiscvAir<SP1Field>>,
    reduce_shape: &SP1RecursionProofShape,
    cache: Option<&SP1NormalizeCache>,
) -> Arc<RecursionProgram<SP1Field>> {
    let shape = SP1NormalizeInputShape {
        proof_shapes: vec![proof_shape.clone()],
        max_log_row_count: verifier.max_log_row_count(),
        log_blowup: verifier.fri_config().log_blowup,
        log_stacking_height: verifier.log_stacking_height() as usize,
    };
    if let Some(program) = cache.as_ref().and_then(|c| c.get(&shape)) {
        return program.clone();
    }

    let input = shape.dummy_input(vk);
    let mut program = normalize_program_from_input(recursive_verifier, &input);
    program.shape = Some(reduce_shape.shape.clone());
    let program = Arc::new(program);
    if let Some(c) = cache {
        c.push(shape, program.clone());
    }
    program
}

pub type CoreProvingKey<C> =
    ProvingKey<SP1GlobalContext, CoreSC, <C as SP1ProverComponents>::CoreProver>;

/// The Core Proving Key cache is initialized once and shared across all setup workers.
pub type CoreProvingKeyCache<C> = Arc<OnceCell<Arc<CoreProvingKey<C>>>>;

/// Worker for handling setup tasks only.
pub struct CoreAndNormalizeWorker<A, C: SP1ProverComponents> {
    artifact_client: A,
    core_prover: Arc<C::CoreProver>,
    permits: ProverSemaphore,
    _marker: std::marker::PhantomData<C>,
}

impl<A, C: SP1ProverComponents> CoreAndNormalizeWorker<A, C> {
    pub fn new(
        artifact_client: A,
        core_prover: Arc<C::CoreProver>,
        permits: ProverSemaphore,
    ) -> Self {
        Self { artifact_client, core_prover, permits, _marker: std::marker::PhantomData }
    }
}

impl<A: ArtifactClient, C: SP1ProverComponents>
    AsyncWorker<SetupTask, Result<(TaskId, TaskMetadata), TaskError>>
    for CoreAndNormalizeWorker<A, C>
{
    async fn call(&self, input: SetupTask) -> Result<(TaskId, TaskMetadata), TaskError> {
        let SetupTask { id, elf, output } = input;

        let elf = self.artifact_client.download_program(&elf).await?;

        let program = Program::from(&elf)?;
        let program = Arc::new(program);

        let permits = self.permits.clone();
        let (_pk, vk) = self.core_prover.setup(program, permits).await;
        tracing::debug!("setup completed for task {}", id);

        // Upload the vk
        self.artifact_client.upload(&output, vk).await.expect("failed to upload vk");
        tracing::debug!("upload completed for artifact {}", output.to_id());

        // TODO: Add the busy time here.
        Ok((id, TaskMetadata::default()))
    }
}

pub type SetupEngine<A, P> = Arc<
    AsyncEngine<SetupTask, Result<(TaskId, TaskMetadata), TaskError>, CoreAndNormalizeWorker<A, P>>,
>;

pub type SetupSubmitHandle<A, C> = SubmitHandle<SetupEngine<A, C>>;

pub struct SP1CoreProver<A, C: SP1ProverComponents> {
    setup_engine: SetupEngine<A, C>,
    air_prover: Arc<C::CoreProver>,
    permits: ProverSemaphore,
}

impl<A: ArtifactClient, C: SP1ProverComponents> Clone for SP1CoreProver<A, C> {
    fn clone(&self) -> Self {
        Self {
            setup_engine: self.setup_engine.clone(),
            air_prover: self.air_prover.clone(),
            permits: self.permits.clone(),
        }
    }
}

impl<A: ArtifactClient, C: SP1ProverComponents> SP1CoreProver<A, C> {
    /// The core AIR prover handle.
    pub fn air_prover(&self) -> Arc<C::CoreProver> {
        self.air_prover.clone()
    }

    /// The GPU permit pool shared with the prove path.
    pub fn permits(&self) -> ProverSemaphore {
        self.permits.clone()
    }

    pub async fn submit_setup(
        &self,
        task: SetupTask,
    ) -> Result<SetupSubmitHandle<A, C>, SubmitError> {
        self.setup_engine.submit(task).await
    }
}

/// Configuration for the core prover.
#[derive(Clone)]
pub struct SP1CoreProverConfig {
    /// The number of setup workers.
    pub num_setup_workers: usize,
    /// The buffer size for the setup.
    pub setup_buffer_size: usize,
}

impl<A: ArtifactClient, C: SP1ProverComponents> SP1CoreProver<A, C> {
    pub fn new(
        config: SP1CoreProverConfig,
        _opts: SP1CoreOpts,
        artifact_client: A,
        air_prover: Arc<C::CoreProver>,
        permits: ProverSemaphore,
    ) -> Self {
        let setup_workers = (0..config.num_setup_workers)
            .map(|_| {
                CoreAndNormalizeWorker::new(
                    artifact_client.clone(),
                    air_prover.clone(),
                    permits.clone(),
                )
            })
            .collect::<Vec<_>>();
        let setup_engine = Arc::new(AsyncEngine::new(setup_workers, config.setup_buffer_size));

        Self { setup_engine, air_prover, permits }
    }
}
