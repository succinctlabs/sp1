//! # CPU Prover Builder
//!
//! This module provides a builder for the [`CpuProver`].

use sp1_core_machine::riscv::RiscvAir;
use sp1_hypercube::Machine;
use sp1_primitives::SP1Field;

use super::CpuProver;
use sp1_core_executor::SP1CoreOpts;

/// A builder for the [`CpuProver`].
///
/// The builder is used to configure the [`CpuProver`] before it is built.
pub struct CpuProverBuilder {
    /// Optional core options to configure the prover.
    core_opts: Option<SP1CoreOpts>,
    machine: Machine<SP1Field, RiscvAir<SP1Field>>,
}

impl Default for CpuProverBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuProverBuilder {
    /// Creates a new [`CpuProverBuilder`] with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_machine(RiscvAir::machine())
    }

    /// Creates a new [`CpuProverBuilder`] with a given machine.
    #[must_use]
    pub const fn new_with_machine(machine: Machine<SP1Field, RiscvAir<SP1Field>>) -> Self {
        Self { core_opts: None, machine }
    }

    /// Sets the core options for the prover.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_core_executor::SP1CoreOpts;
    /// use sp1_sdk::ProverClient;
    ///
    /// tokio_test::block_on(async {
    ///     let mut opts = SP1CoreOpts::default();
    ///     opts.shard_size = 500_000;
    ///     let prover = ProverClient::builder().cpu().core_opts(opts).build().await;
    /// });
    /// ```
    #[must_use]
    pub fn core_opts(mut self, opts: SP1CoreOpts) -> Self {
        self.core_opts = Some(opts);
        self
    }

    /// Sets the core options for the prover (alias for `core_opts`).
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_core_executor::SP1CoreOpts;
    /// use sp1_sdk::ProverClient;
    ///
    /// tokio_test::block_on(async {
    ///     let mut opts = SP1CoreOpts::default();
    ///     opts.shard_size = 500_000;
    ///     let prover = ProverClient::builder().cpu().with_opts(opts).build().await;
    /// });
    /// ```
    #[must_use]
    pub fn with_opts(self, opts: SP1CoreOpts) -> Self {
        self.core_opts(opts)
    }

    /// Builds a [`CpuProver`].
    ///
    /// # Details
    /// This method will build a [`CpuProver`] with the given parameters. In particular, it will
    /// build a mock prover if the `mock` flag is set.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// tokio_test::block_on(async {
    ///     let prover = ProverClient::builder().cpu().build().await;
    /// });
    /// ```
    #[must_use]
    pub async fn build(self) -> CpuProver {
        CpuProver::new_with_opts_and_machine(self.core_opts, self.machine).await
    }
}
