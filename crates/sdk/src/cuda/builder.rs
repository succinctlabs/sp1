//! # CUDA Prover Builder
//!
//! This module provides a builder for the [`CudaProver`].

use super::CudaProver;
use sp1_core_executor::SP1CoreOpts;
use sp1_core_machine::riscv::RiscvAir;
use sp1_cuda::CudaProver as CudaProverImpl;
use sp1_hypercube::Machine;
use sp1_primitives::SP1Field;
use sp1_prover::worker::SP1LightNode;

/// A builder for the [`CudaProver`].
///
/// The builder is used to configure the [`CudaProver`] before it is built.
pub struct CudaProverBuilder {
    cuda_device_id: Option<u32>,
    /// Optional core options to configure the underlying CPU prover.
    core_opts: Option<SP1CoreOpts>,
    machine: Machine<SP1Field, RiscvAir<SP1Field>>,
}

impl Default for CudaProverBuilder {
    fn default() -> Self {
        Self::new_with_machine(RiscvAir::machine())
    }
}

impl CudaProverBuilder {
    /// Creates a new [`CudaProverBuilder`] with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_machine(RiscvAir::machine())
    }

    /// Creates a new builder from a machine.
    #[must_use]
    pub fn new_with_machine(machine: Machine<SP1Field, RiscvAir<SP1Field>>) -> Self {
        Self { machine, cuda_device_id: None, core_opts: None }
    }

    /// Sets the CUDA device id.
    ///
    /// # Details
    /// Run the CUDA prover with the provided device id, all operations will be performed on this
    /// device index.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let prover = ProverClient::builder().cuda().with_device_id(0).build();
    /// ```
    #[must_use]
    pub fn with_device_id(mut self, id: u32) -> Self {
        self.cuda_device_id = Some(id);
        self
    }

    /// Sets the core options for the underlying CPU prover.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_core_executor::SP1CoreOpts;
    /// use sp1_sdk::ProverClient;
    ///
    /// tokio_test::block_on(async {
    ///     let mut opts = SP1CoreOpts::default();
    ///     opts.shard_size = 500_000;
    ///     let prover = ProverClient::builder().cuda().core_opts(opts).build().await;
    /// });
    /// ```
    #[must_use]
    pub fn core_opts(mut self, opts: SP1CoreOpts) -> Self {
        self.core_opts = Some(opts);
        self
    }

    /// Sets the core options for the underlying CPU prover (alias for `core_opts`).
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_core_executor::SP1CoreOpts;
    /// use sp1_sdk::ProverClient;
    ///
    /// tokio_test::block_on(async {
    ///     let mut opts = SP1CoreOpts::default();
    ///     opts.shard_size = 500_000;
    ///     let prover = ProverClient::builder().cuda().with_opts(opts).build().await;
    /// });
    /// ```
    #[must_use]
    pub fn with_opts(self, opts: SP1CoreOpts) -> Self {
        self.core_opts(opts)
    }

    /// Builds a [`CudaProver`].
    ///
    /// # Details
    /// This method will build a [`CudaProver`] with the given parameters.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let prover = ProverClient::builder().cuda().build();
    /// ```
    #[must_use]
    pub async fn build(self) -> CudaProver {
        tracing::info!("initializing cuda prover");
        let machine = self.machine;
        let node =
            SP1LightNode::with_opts_and_machine(machine, self.core_opts.unwrap_or_default()).await;
        let cuda_prover = match self.cuda_device_id {
            Some(id) => CudaProverImpl::new_with_id(id).await,
            None => CudaProverImpl::new().await,
        };

        CudaProver { node, prover: cuda_prover.expect("Failed to create the CUDA prover impl") }
    }
}
