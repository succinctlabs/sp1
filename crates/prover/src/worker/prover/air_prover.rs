use std::{future::Future, sync::Arc};

use slop_challenger::IopCtx;
use sp1_core_executor::ExecutionRecord;
use sp1_hypercube::{
    prover::{AirProver, PcsProof, Program, ProverPermit, ProverSemaphore, ProvingKey, Record},
    Chip, Machine, MachineVerifyingKey, ShardContext, ShardContextProof, ShardProof,
};

/// A prover for an AIR.
pub trait AirProverWorker<GC: IopCtx, SC: ShardContext<GC>, P: AirProver<GC, SC>>:
    'static + Send + Sync
{
    /// Setup from a program.
    ///
    /// The setup phase produces a verifying key.
    #[allow(clippy::type_complexity)]
    fn setup(
        &self,
        program: Arc<Program<GC, SC>>,
        setup_permits: ProverSemaphore,
    ) -> impl Future<Output = (Arc<ProvingKey<GC, SC, P>>, MachineVerifyingKey<GC>)> + Send;

    /// Get the machine.
    fn machine(&self) -> &Machine<GC::F, SC::Air>;

    /// Setup and prove a shard.
    fn setup_and_prove_shard(
        &self,
        program: Arc<Program<GC, SC>>,
        record: Record<GC, SC>,
        vk: Option<MachineVerifyingKey<GC>>,
        prover_permits: ProverSemaphore,
    ) -> impl Future<Output = (MachineVerifyingKey<GC>, ShardContextProof<GC, SC>, ProverPermit)> + Send;
    /// Setup and prove a shard.
    fn prove_shard_with_pk(
        &self,
        pk: Arc<ProvingKey<GC, SC, P>>,
        record: Record<GC, SC>,
        prover_permits: ProverSemaphore,
    ) -> impl Future<Output = (ShardProof<GC, PcsProof<GC, SC>>, ProverPermit)> + Send;

    /// Generate the chunk's global commitment for the `ExecutionRecord`.
    fn generate_global_commitment(
        &self,
        record: &ExecutionRecord,
        permits: ProverSemaphore,
    ) -> impl Future<Output = GC::Digest> + Send
    where
        ExecutionRecord: Into<Record<GC, SC>>;

    /// Prove a shard from its [`ExecutionRecord`] and the chunk's ordered global commitments.
    fn prove_shard(
        &self,
        program: Arc<Program<GC, SC>>,
        record: &ExecutionRecord,
        commitments: &[GC::Digest],
        permits: ProverSemaphore,
    ) -> impl Future<Output = ShardProof<GC, PcsProof<GC, SC>>> + Send
    where
        ExecutionRecord: Into<Record<GC, SC>>;

    /// Get all the chips in the machine.
    fn all_chips(&self) -> &[Chip<GC::F, SC::Air>] {
        self.machine().chips()
    }
}

impl<GC, SC, P> AirProverWorker<GC, SC, P> for P
where
    GC: IopCtx,
    SC: ShardContext<GC>,
    P: AirProver<GC, SC>,
{
    async fn setup(
        &self,
        program: Arc<Program<GC, SC>>,
        setup_permits: ProverSemaphore,
    ) -> (Arc<ProvingKey<GC, SC, P>>, MachineVerifyingKey<GC>) {
        let (preprocessed, vk) = self.setup(program, setup_permits).await;
        (preprocessed.pk, vk)
    }

    /// Get the machine.
    fn machine(&self) -> &Machine<GC::F, SC::Air> {
        AirProver::machine(self)
    }

    /// Setup and prove a shard.
    async fn setup_and_prove_shard(
        &self,
        program: Arc<Program<GC, SC>>,
        record: Record<GC, SC>,
        vk: Option<MachineVerifyingKey<GC>>,
        prover_permits: ProverSemaphore,
    ) -> (MachineVerifyingKey<GC>, ShardProof<GC, PcsProof<GC, SC>>, ProverPermit) {
        AirProver::setup_and_prove_shard(self, program, record, vk, prover_permits).await
    }

    /// Prove a shard from a given pk.
    async fn prove_shard_with_pk(
        &self,
        pk: Arc<ProvingKey<GC, SC, P>>,
        record: Record<GC, SC>,
        prover_permits: ProverSemaphore,
    ) -> (ShardProof<GC, PcsProof<GC, SC>>, ProverPermit) {
        AirProver::prove_shard_with_pk(self, pk, record, prover_permits).await
    }

    async fn generate_global_commitment(
        &self,
        record: &ExecutionRecord,
        permits: ProverSemaphore,
    ) -> GC::Digest
    where
        ExecutionRecord: Into<Record<GC, SC>>,
    {
        self.commit_global_traces_for_record(record.clone().into(), permits).await
    }

    async fn prove_shard(
        &self,
        program: Arc<Program<GC, SC>>,
        record: &ExecutionRecord,
        commitments: &[GC::Digest],
        permits: ProverSemaphore,
    ) -> ShardProof<GC, PcsProof<GC, SC>>
    where
        ExecutionRecord: Into<Record<GC, SC>>,
    {
        let mut record = record.clone();
        record.set_global_commitments::<GC>(commitments);
        let (_vk, proof, _permit) =
            self.setup_and_prove_shard(program, record.into(), None, permits).await;
        proof
    }
}
