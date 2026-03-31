//! # SP1 Prover Client
//!
//! A client for interacting with the prover for the SP1 RISC-V zkVM.

use crate::blocking::{
    cpu::builder::CpuProverBuilder, cuda::builder::CudaProverBuilder, env::EnvProver,
    light::builder::LightProverBuilder, mock::builder::MockProverBuilder,
};
use sp1_core_machine::riscv::RiscvAir;
use sp1_hypercube::Machine;
use sp1_primitives::SP1Field;

/// An entrypoint for interacting with the prover for the SP1 RISC-V zkVM.
///
/// IMPORTANT: `ProverClient` only needs to be initialized ONCE and can be reused for subsequent
/// proving operations, all provers types are cheap to clone and share across threads.
///
/// Note that the initialization may be slow as it loads necessary proving parameters and sets up
/// the environment.
pub struct ProverClient;

impl ProverClient {
    /// Builds an [`EnvProver`], which loads the mode and any settings from the environment.
    ///
    /// # Usage
    /// ```no_run
    /// use sp1_sdk::blocking::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// std::env::set_var("SP1_PROVER", "cuda");
    /// let prover = ProverClient::from_env();
    ///
    /// let elf = Elf::Static(&[1, 2, 3]);
    /// let stdin = SP1Stdin::new();
    ///
    /// let pk = prover.setup(elf).unwrap();
    /// let proof = prover.prove(&pk, stdin).compressed().run().unwrap();
    /// ```
    #[must_use]
    pub fn from_env() -> EnvProver {
        EnvProver::new(RiscvAir::machine())
    }

    /// Same as `from_env` but with a custom machine.
    #[must_use]
    pub fn from_env_with_machine(machine: Machine<SP1Field, RiscvAir<SP1Field>>) -> EnvProver {
        EnvProver::new(machine)
    }

    /// Creates a new [`ProverClientBuilder`] so that you can configure the prover client.
    #[must_use]
    pub fn builder() -> ProverClientBuilder {
        Self::builder_with_machine(RiscvAir::machine())
    }

    /// Creates a new [`ProverClientBuilder`] so that you can configure the prover client.
    #[must_use]
    pub fn builder_with_machine(
        machine: Machine<SP1Field, RiscvAir<SP1Field>>,
    ) -> ProverClientBuilder {
        ProverClientBuilder { machine }
    }
}

/// A builder to define which proving client to use.
pub struct ProverClientBuilder {
    machine: Machine<SP1Field, RiscvAir<SP1Field>>,
}

impl ProverClientBuilder {
    /// Builds a [`CpuProver`] specifically for local CPU proving.
    ///
    /// # Usage
    /// ```no_run
    /// use sp1_sdk::blocking::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// let elf = Elf::Static(&[1, 2, 3]);
    /// let stdin = SP1Stdin::new();
    ///
    /// let prover = ProverClient::builder().cpu().build();
    /// let pk = prover.setup(elf).unwrap();
    /// let proof = prover.prove(&pk, stdin).compressed().run().unwrap();
    /// ```
    #[must_use]
    #[allow(clippy::unused_self)]
    pub fn cpu(&self) -> CpuProverBuilder {
        CpuProverBuilder::new(self.machine.clone())
    }

    /// Builds a [`CudaProver`] specifically for local proving on NVIDIA GPUs.
    ///
    /// # Example
    /// ```no_run
    /// use sp1_sdk::blocking::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// let elf = Elf::Static(&[1, 2, 3]);
    /// let stdin = SP1Stdin::new();
    ///
    /// let prover = ProverClient::builder().cuda().build();
    /// let pk = prover.setup(elf).unwrap();
    /// let proof = prover.prove(&pk, stdin).compressed().run().unwrap();
    /// ```
    #[must_use]
    #[allow(clippy::unused_self)]
    pub fn cuda(&self) -> CudaProverBuilder {
        CudaProverBuilder::new(self.machine.clone())
    }

    /// Builds a [`MockProver`] for testing without real proving or verification.
    #[must_use]
    #[allow(clippy::unused_self)]
    pub fn mock(&self) -> MockProverBuilder {
        MockProverBuilder::new(self.machine.clone())
    }

    /// Builds a [`LightProver`] that only executes and verifies but does not generate proofs.
    #[must_use]
    #[allow(clippy::unused_self)]
    pub fn light(&self) -> LightProverBuilder {
        LightProverBuilder::new(self.machine.clone())
    }
}
