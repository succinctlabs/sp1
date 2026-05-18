use std::{future::Future, sync::Arc};

use slop_algebra::AbstractField;
use slop_challenger::IopCtx;
use slop_symmetric::CryptographicHasher;
use sp1_core_executor::ExecutionRecord;
use sp1_hypercube::{
    air::PROOF_NONCE_NUM_WORDS,
    prover::{AirProver, PcsProof, Program, ProverPermit, ProverSemaphore, ProvingKey, Record},
    Chip, Machine, MachineVerifyingKey, ShardContext, ShardContextProof, ShardProof,
};

use crate::worker::controller::MerkleProvingInput;

/// Bench-only stub configuration.
#[cfg(feature = "bench-stub")]
pub mod bench_stub {
    use std::any::Any;
    use std::collections::BTreeSet;
    use std::sync::{Arc, OnceLock};

    use sp1_core_machine::riscv::RiscvAir;
    use sp1_primitives::{fri_params::core_fri_config, SP1Field};
    use sp1_recursion_circuit::dummy::dummy_shard_proof;

    use crate::{CORE_LOG_STACKING_HEIGHT, CORE_MAX_LOG_ROW_COUNT};

    pub struct BenchStubConfig {
        pub commit_ms: u64,
        pub merkle_prep_ms: u64,
        pub prove_ms: u64,
        pub stub_proof: Arc<dyn Any + Send + Sync>,
    }

    impl BenchStubConfig {
        /// Build a config with a dummy proof.
        pub fn with_core_stub_proof(commit_ms: u64, merkle_prep_ms: u64, prove_ms: u64) -> Self {
            let stub_proof = dummy_shard_proof::<RiscvAir<SP1Field>>(
                BTreeSet::new(),
                CORE_MAX_LOG_ROW_COUNT,
                core_fri_config(),
                CORE_LOG_STACKING_HEIGHT as usize,
                &[0, 0],
                &[0, 0],
            );
            Self { commit_ms, merkle_prep_ms, prove_ms, stub_proof: Arc::new(stub_proof) }
        }
    }

    pub(super) static CONFIG: OnceLock<BenchStubConfig> = OnceLock::new();

    /// Install the bench stub.
    pub fn install(cfg: BenchStubConfig) -> Result<(), &'static str> {
        CONFIG.set(cfg).map_err(|_| "bench_stub config already installed")
    }
}

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

    /// Prepare the batch merkle proof for a chunk's memory updates.
    /// TODO(rkm): decide whether or not to split the proof here.
    /// Currently a stub implementation.
    fn prepare_merkle_proof(
        &self,
        input: MerkleProvingInput,
        program: Arc<sp1_core_executor::Program>,
        proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
        global_dependencies_opt: bool,
        permits: ProverSemaphore,
    ) -> impl Future<Output = ExecutionRecord> + Send {
        async move {
            let _permit = permits.acquire().await;
            #[cfg(feature = "bench-stub")]
            if let Some(cfg) = bench_stub::CONFIG.get() {
                tokio::time::sleep(std::time::Duration::from_millis(cfg.merkle_prep_ms)).await;
            }
            ExecutionRecord::from_merkle_payload(
                program,
                proof_nonce,
                global_dependencies_opt,
                input.payload,
            )
        }
    }

    /// Generate the global commitment the `ExecutionRecord`.
    /// Currently a stub implementation.
    fn generate_global_commitment(
        &self,
        _record: &ExecutionRecord,
        permits: ProverSemaphore,
    ) -> impl Future<Output = GC::Digest> + Send {
        async move {
            let _permit = permits.acquire().await;
            #[cfg(feature = "bench-stub")]
            if let Some(cfg) = bench_stub::CONFIG.get() {
                tokio::time::sleep(std::time::Duration::from_millis(cfg.commit_ms)).await;
            }
            let (hasher, _) = GC::default_hasher_and_compressor();
            hasher.hash_iter(core::iter::once(GC::F::from_canonical_u32(0)))
        }
    }

    /// Prove a shard from its [`ExecutionRecord`] and the ordered global
    /// commitments for the chunk. Currently a stub.
    fn prove_shard(
        &self,
        _record: &ExecutionRecord,
        _commitments: &[GC::Digest],
        permits: ProverSemaphore,
    ) -> impl Future<Output = ShardProof<GC, PcsProof<GC, SC>>> + Send {
        async move {
            let _permit = permits.acquire().await;
            #[cfg(feature = "bench-stub")]
            if let Some(cfg) = bench_stub::CONFIG.get() {
                tokio::time::sleep(std::time::Duration::from_millis(cfg.prove_ms)).await;
                let any_ref: &dyn std::any::Any = &*cfg.stub_proof;
                let stub = any_ref.downcast_ref::<ShardProof<GC, PcsProof<GC, SC>>>().unwrap();
                return stub.clone();
            }
            todo!("prove_shard stub")
        }
    }

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
}
