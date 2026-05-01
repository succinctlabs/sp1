use std::sync::Arc;

use sp1_core_executor::{ExecutionReport, Program, SP1Context, SP1CoreOpts};
use sp1_core_machine::io::SP1Stdin;
use sp1_core_machine::riscv::RiscvAir;
use sp1_hypercube::{
    prover::{CpuShardProver, ProverSemaphore},
    Machine, SP1VerifyingKey,
};
use sp1_primitives::{io::SP1PublicValues, SP1Field};
use sp1_verifier::SP1Proof;

#[cfg(not(feature = "mprotect"))]
use crate::verify::VerifierRecursionVks;
#[cfg(feature = "mprotect")]
use crate::{recursion::RecursionVks, worker::DEFAULT_MAX_COMPOSE_ARITY};
use crate::{
    verify::SP1Verifier,
    worker::{node::SP1NodeCore, AirProverWorker},
    CpuSP1ProverComponents, SP1ProverComponents,
};

struct SP1LightNodeInner {
    /// The core node is used to execute the program and verify the proof
    core: SP1NodeCore,
    /// The core air prover is used to do the setup step
    core_air_prover: Arc<<CpuSP1ProverComponents as SP1ProverComponents>::CoreProver>,
    /// The permits are used to limit the number of concurrent provers
    permits: ProverSemaphore,
}

pub struct SP1LightNode {
    inner: Arc<SP1LightNodeInner>,
}

impl Clone for SP1LightNode {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl SP1LightNode {
    pub async fn new() -> Self {
        Self::new_with_machine(RiscvAir::machine()).await
    }

    pub async fn new_with_machine(machine: Machine<SP1Field, RiscvAir<SP1Field>>) -> Self {
        Self::with_opts_and_machine(machine, SP1CoreOpts::default()).await
    }

    /// Create a new light node with custom options.
    pub async fn with_opts(opts: SP1CoreOpts) -> Self {
        Self::with_opts_and_machine(RiscvAir::machine(), opts).await
    }

    /// Create a new light node with custom options and a given machine.
    pub async fn with_opts_and_machine(
        machine: Machine<SP1Field, RiscvAir<SP1Field>>,
        opts: SP1CoreOpts,
    ) -> Self {
        // Initializing the merkle tree is blocking, so we need to spawn in on a blocking task.
        tokio::task::spawn_blocking(move || {
            // Get a core prover for the light node to be able to do the setup step
            let core_verifier = CpuSP1ProverComponents::core_verifier(machine.clone());
            let core_air_prover =
                Arc::new(CpuShardProver::new(core_verifier.shard_verifier().clone()));
            let permits = ProverSemaphore::new(1);

            #[cfg(feature = "mprotect")]
            let verifier_vks =
                RecursionVks::new(None, DEFAULT_MAX_COMPOSE_ARITY, false).to_verifier_vks();
            #[cfg(not(feature = "mprotect"))]
            let verifier_vks = VerifierRecursionVks::default();
            let verifier = SP1Verifier::new_with_machine(verifier_vks, machine);
            // Create a new core node for the light node
            let core = SP1NodeCore::new(verifier, opts);

            Self { inner: Arc::new(SP1LightNodeInner { core, core_air_prover, permits }) }
        })
        .await
        .expect("failed to initialize light node")
    }

    pub async fn setup(&self, elf: &[u8]) -> anyhow::Result<SP1VerifyingKey> {
        let program = Program::from(elf)
            .map_err(|e| anyhow::anyhow!("failed to disassemble program: {}", e))?;
        let program = Arc::new(program);
        let (_, vk) = self.inner.core_air_prover.setup(program, self.inner.permits.clone()).await;
        let vk = SP1VerifyingKey { vk };
        Ok(vk)
    }

    /// Execute a program
    pub async fn execute(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
        context: SP1Context<'static>,
    ) -> anyhow::Result<(SP1PublicValues, [u8; 32], ExecutionReport)> {
        self.inner.core.execute(elf, stdin, context).await
    }

    /// Verify a proof
    pub fn verify(&self, vk: &SP1VerifyingKey, proof: &SP1Proof) -> anyhow::Result<()> {
        self.inner.core.verify(vk, proof)
    }

    #[inline]
    pub fn inner(&self) -> &SP1NodeCore {
        &self.inner.core
    }
}

#[cfg(test)]
mod tests {
    use sp1_core_machine::utils::setup_logger;
    use sp1_hypercube::HashableKey;
    use tracing::Instrument;

    use crate::worker::{cpu_worker_builder_with_machine, SP1LocalNodeBuilder};

    use super::*;

    #[tokio::test]
    async fn test_light_node() {
        setup_logger();

        let machine = RiscvAir::machine();
        let light_node = SP1LightNode::new_with_machine(machine.clone())
            .instrument(tracing::info_span!("initialize light node"))
            .await;

        let node = SP1LocalNodeBuilder::from_worker_client_builder(
            cpu_worker_builder_with_machine(machine),
        )
        .build()
        .instrument(tracing::info_span!("initialize full node"))
        .await
        .unwrap();

        let elf = test_artifacts::FIBONACCI_ELF;
        let stdin = SP1Stdin::default();

        // Execute the program with the light node
        let context = SP1Context::default();
        let (_, _, report) =
            light_node.execute(&elf, stdin.clone(), context.clone()).await.unwrap();
        tracing::info!("report: {:?}", report);
        // Setup the program with the light node
        let light_node_vk = light_node.setup(&elf).await.unwrap();
        // Prove the program with the full node
        let node_vk = node.setup(&elf).await.unwrap();
        // Check that they are equal by comparing the digests
        assert_eq!(light_node_vk.hash_koalabear(), node_vk.hash_koalabear());

        // Prove the program with the full node
        let proof = node.prove(&elf, stdin, context).await.unwrap();
        // verify the proof with the light node
        light_node.verify(&light_node_vk, &proof.proof).unwrap();

        let node_vks = node.core().recursion_vks();
        let light_node_vks = light_node.inner().recursion_vks();
        assert_eq!(node_vks, light_node_vks, "If this assertion fails, run test `sp1_prover::worker::node::full::tests::make_verifier_vks`");
    }
}
