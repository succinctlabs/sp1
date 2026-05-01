//! # SP1 CPU Prover
//!
//! A prover that uses the CPU to execute and prove programs.

pub mod builder;
pub mod prove;

use std::sync::Arc;

use anyhow::Result;
use prove::CpuProveBuilder;
use sp1_core_executor::ExecutionError;
use sp1_core_machine::io::SP1Stdin;
use sp1_core_machine::riscv::RiscvAir;
use sp1_hypercube::Machine;
use sp1_primitives::{Elf, SP1Field};
use sp1_prover::worker::{
    cpu_worker_builder_with_machine, SP1LocalNode, SP1LocalNodeBuilder, SP1NodeCore, TaskError,
};

use crate::blocking::prover::Prover;
use crate::SP1ProvingKey;

use thiserror::Error;

/// A prover that uses the CPU to execute and prove programs.
#[derive(Clone)]
pub struct CpuProver {
    pub(crate) prover: Arc<SP1LocalNode>,
}

impl Default for CpuProver {
    fn default() -> Self {
        Self::new()
    }
}

/// An error occurred while proving.
#[derive(Debug, Error)]
pub enum CPUProverError {
    /// An error occurred while proving.
    #[error(transparent)]
    Prover(#[from] TaskError),

    /// An error occurred while executing.
    #[error(transparent)]
    Execution(#[from] ExecutionError),

    /// An unexpected error occurred.
    #[error("An unexpected error occurred: {:?}", .0)]
    Unexpected(#[from] anyhow::Error),
}

impl Prover for CpuProver {
    type ProvingKey = SP1ProvingKey;
    type Error = CPUProverError;
    type ProveRequest<'a> = CpuProveBuilder<'a>;

    fn inner(&self) -> &SP1NodeCore {
        self.prover.core()
    }

    fn setup(&self, elf: Elf) -> Result<Self::ProvingKey, Self::Error> {
        crate::blocking::block_on(async move {
            let vk = self.prover.setup(&elf).await?;
            Ok(SP1ProvingKey { vk, elf })
        })
    }

    fn prove<'a>(&'a self, pk: &'a Self::ProvingKey, stdin: SP1Stdin) -> Self::ProveRequest<'a> {
        CpuProveBuilder::new(self, pk, stdin)
    }
}

impl CpuProver {
    /// Creates a new [`CpuProver`], using the default [`LocalProverOpts`].
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_machine(RiscvAir::machine())
    }

    /// Creates a new [`CpuProver`], using the default [`LocalProverOpts`] and a given machine.
    #[must_use]
    pub fn new_with_machine(machine: Machine<SP1Field, RiscvAir<SP1Field>>) -> Self {
        Self::new_with_opts_and_machine(None, machine)
    }

    /// Creates a new [`CpuProver`] with optional custom [`SP1CoreOpts`].
    #[must_use]
    pub fn new_with_opts(core_opts: Option<sp1_core_executor::SP1CoreOpts>) -> Self {
        Self::new_with_opts_and_machine(core_opts, RiscvAir::machine())
    }

    /// Creates a new [`CpuProver`] with optional custom [`SP1CoreOpts`] and a given machine.
    #[must_use]
    pub fn new_with_opts_and_machine(
        core_opts: Option<sp1_core_executor::SP1CoreOpts>,
        machine: Machine<SP1Field, RiscvAir<SP1Field>>,
    ) -> Self {
        tracing::info!("initializing cpu prover");
        let worker_builder =
            cpu_worker_builder_with_machine(machine).with_core_opts(core_opts.unwrap_or_default());
        let prover = Arc::new(
            crate::blocking::block_on(
                SP1LocalNodeBuilder::from_worker_client_builder(worker_builder).build(),
            )
            .unwrap(),
        );
        Self { prover }
    }

    /// # ⚠️ WARNING: This prover is experimental and should not be used in production.
    /// It is intended for development and debugging purposes.
    ///
    /// Creates a new [`CpuProver`], using the default [`LocalProverOpts`].
    /// Verification of the proof system's verification key is skipped, meaning that the
    /// recursion proofs are not guaranteed to be about a permitted recursion program.
    #[cfg(feature = "experimental")]
    #[must_use]
    pub fn new_experimental() -> Self {
        Self::new_experimental_with_machine(RiscvAir::machine())
    }

    /// Same as [`Self::new_experimental`] but with a custom machine.
    #[cfg(feature = "experimental")]
    #[must_use]
    pub fn new_experimental_with_machine(machine: Machine<SP1Field, RiscvAir<SP1Field>>) -> Self {
        Self::new_with_opts_and_machine(None, machine)
    }
}
