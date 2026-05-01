/// The shared API between the client and server.
pub mod api;

/// The client that interacts with the CUDA server.
pub mod client;

/// The proving key type, which is a "remote" reference to a key held by the CUDA server.
pub mod pk;

/// The server startup logic.
mod server;

mod error;
pub use error::CudaClientError;

pub use pk::CudaProvingKey;
use sp1_core_executor::SP1Context;
use sp1_core_machine::io::SP1Stdin;
use sp1_core_machine::riscv::RiscvAir;
use sp1_hypercube::Machine;
use sp1_primitives::{Elf, SP1Field};
use sp1_prover::worker::ProofFromNetwork;
use sp1_prover_types::network_base_types::ProofMode;

use crate::client::CudaClient;

#[derive(Clone)]
pub struct CudaProver {
    client: CudaClient,
}

impl CudaProver {
    /// Create a new prover, using the 0th CUDA device.
    pub async fn new() -> Result<Self, CudaClientError> {
        Ok(Self { client: CudaClient::connect(0).await? })
    }

    /// Create a new prover, using the given CUDA device.
    pub async fn new_with_id(cuda_id: u32) -> Result<Self, CudaClientError> {
        Ok(Self { client: CudaClient::connect(cuda_id).await? })
    }

    /// Setup a new proving key.
    pub async fn setup(&self, elf: Elf) -> Result<CudaProvingKey, CudaClientError> {
        self.setup_with_machine(elf, RiscvAir::machine()).await
    }

    /// Same as [`Self::setup`] but with a custom machine.
    pub async fn setup_with_machine(
        &self,
        elf: Elf,
        machine: Machine<SP1Field, RiscvAir<SP1Field>>,
    ) -> Result<CudaProvingKey, CudaClientError> {
        self.client.setup(elf, machine).await
    }

    pub async fn prove_with_mode(
        &self,
        pk: &CudaProvingKey,
        stdin: SP1Stdin,
        context: SP1Context<'static>,
        mode: ProofMode,
    ) -> Result<ProofFromNetwork, CudaClientError> {
        self.client.prove_with_mode(pk, stdin, context, mode).await
    }
}
