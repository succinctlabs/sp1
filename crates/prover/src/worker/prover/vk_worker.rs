use sp1_core_machine::riscv::RiscvAir;
use sp1_hypercube::{log2_ceil_usize, prover::ProverSemaphore, Machine};
use sp1_primitives::SP1Field;
use sp1_prover_types::ArtifactClient;

use crate::{
    shapes::build_vk_map,
    worker::{RawTaskRequest, ShrinkProver, TaskError, VkeyMapChunkInput, VkeyMapChunkOutput},
    SP1ProverComponents,
};
use std::sync::Arc;

pub struct RecursionVkWorker<C: SP1ProverComponents> {
    pub recursion_prover: Arc<C::RecursionProver>,
    pub recursion_permits: ProverSemaphore,
    pub shrink_prover: Arc<ShrinkProver<C>>,
}

impl<C: SP1ProverComponents> Clone for RecursionVkWorker<C> {
    fn clone(&self) -> Self {
        Self {
            recursion_prover: self.recursion_prover.clone(),
            recursion_permits: self.recursion_permits.clone(),
            shrink_prover: self.shrink_prover.clone(),
        }
    }
}

pub async fn run_vk_generation<A: ArtifactClient, C: SP1ProverComponents>(
    worker: Arc<RecursionVkWorker<C>>,
    request: RawTaskRequest,
    client: A,
    machine: Machine<SP1Field, RiscvAir<SP1Field>>,
) -> Result<(), TaskError> {
    let RawTaskRequest { inputs, outputs, .. } = request;

    let VkeyMapChunkInput { indices, reduce_batch_size, total_inputs } =
        client.download(&inputs[0]).await?;

    let (vk_set, panic_indices) = build_vk_map::<A, C>(
        false,
        1,
        1,
        Some(indices),
        reduce_batch_size,
        log2_ceil_usize(total_inputs),
        worker,
        machine,
    )
    .await;

    let output = VkeyMapChunkOutput { vk_set, panic_indices };

    client.upload(&outputs[0], &output).await?;

    Ok(())
}
