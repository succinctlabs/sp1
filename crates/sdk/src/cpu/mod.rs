//! # SP1 CPU Prover
//!
//! A prover that uses the CPU to execute and prove programs.

pub mod builder;
pub mod prove;

use std::sync::Arc;

use prove::CpuProveBuilder;
use sp1_core_executor::ExecutionError;
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::Elf;
use sp1_prover::worker::{
    cpu_worker_builder, SP1LocalNode, SP1LocalNodeBuilder, SP1NodeCore, TaskError,
};

use crate::{
    prover::{Prover, SendFutureResult},
    SP1ProvingKey,
};

use thiserror::Error;

/// A prover that uses the CPU to execute and prove programs.
#[derive(Clone)]
pub struct CpuProver {
    pub(crate) prover: Arc<SP1LocalNode>,
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

    fn setup(&self, elf: Elf) -> impl SendFutureResult<Self::ProvingKey, Self::Error> {
        async move {
            let vk = self.prover.setup(&elf).await?;
            Ok(SP1ProvingKey { vk, elf })
        }
    }

    fn prove<'a>(&'a self, pk: &'a Self::ProvingKey, stdin: SP1Stdin) -> Self::ProveRequest<'a> {
        CpuProveBuilder::new(self, pk, stdin)
    }
}

impl CpuProver {
    /// Creates a new [`CpuProver`], using the default [`LocalProverOpts`].
    #[must_use]
    pub async fn new() -> Self {
        Self::new_with_opts(None).await
    }

    /// Creates a new [`CpuProver`] with optional custom [`SP1CoreOpts`].
    #[must_use]
    pub async fn new_with_opts(core_opts: Option<sp1_core_executor::SP1CoreOpts>) -> Self {
        tracing::info!("initializing cpu prover");
        let worker_builder = cpu_worker_builder().with_core_opts(core_opts.unwrap_or_default());
        Self {
            prover: Arc::new(
                SP1LocalNodeBuilder::from_worker_client_builder(worker_builder)
                    .build()
                    .await
                    .unwrap(),
            ),
        }
    }

    /// # ⚠️ WARNING: This prover is experimental and should not be used in production.
    /// It is intended for development and debugging purposes.
    ///
    /// Creates a new [`CpuProver`], using the default [`LocalProverOpts`].
    /// Verification of the proof system's verification key is skipped, meaning that the
    /// recursion proofs are not guaranteed to be about a permitted recursion program.
    #[cfg(feature = "experimental")]
    #[must_use]
    pub async fn new_experimental() -> Self {
        Self::new_with_opts(None).await
    }
}
