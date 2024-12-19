//! # CPU Execution
//!
//! This module provides a builder for simulating the execution of a program on the CPU.

use anyhow::Result;
use sp1_core_executor::{ExecutionReport, HookEnv, SP1ContextBuilder};
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::io::SP1PublicValues;
use sp1_prover::{components::CpuProverComponents, SP1Prover};

/// A builder for simulating the execution of a program on the CPU.
///
/// This builder providers a typed interface for configuring the SP1 RISC-V executor. The builder
/// is used for all the different variants of the [`crate::ProverClient`].
pub struct CpuExecuteBuilder<'a> {
    pub(crate) elf: &'a [u8],
    pub(crate) stdin: SP1Stdin,
    pub(crate) prover: &'a SP1Prover<CpuProverComponents>,
    pub(crate) context_builder: SP1ContextBuilder<'a>,
}

impl<'a> CpuExecuteBuilder<'a> {
    /// Add a executor [`sp1_core_executor::Hook`] into the context.
    ///
    /// # Arguments
    /// * `fd` - The file descriptor that triggers this execution hook.
    /// * `f` - The function to invoke when the hook is triggered.
    ///
    /// # Details
    /// Hooks may be invoked from within SP1 by writing to the specified file descriptor `fd`
    /// with [`sp1_zkvm::io::write`], returning a list of arbitrary data that may be read
    /// with successive calls to [`sp1_zkvm::io::read`].
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin, include_elf, Prover};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let builder = client.execute(elf, &stdin)
    ///     .with_hook(1, |env, data| {
    ///         println!("Hook triggered with data: {:?}", data);
    ///         vec![vec![1, 2, 3]]
    ///     })
    ///     .run();
    /// ```
    #[must_use]
    pub fn with_hook(
        mut self,
        fd: u32,
        f: impl FnMut(HookEnv, &[u8]) -> Vec<Vec<u8>> + Send + Sync + 'a,
    ) -> Self {
        self.context_builder.hook(fd, f);
        self
    }

    /// Set the maximum number of cpu cycles to use for execution.
    ///
    /// # Arguments
    /// * `max_cycles` - The maximum number of cycles to use for execution.
    ///
    /// # Details
    /// If the cycle limit is exceeded, execution will fail with the
    /// [`sp1_core_executor::ExecutionError::ExceededCycleLimit`]. This is useful for preventing
    /// infinite loops in the and limiting the execution time of the program.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin, include_elf, Prover};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let builder = client.execute(elf, &stdin)
    ///     .cycle_limit(1000000)
    ///     .run();
    /// ```
    #[must_use]
    pub fn cycle_limit(mut self, max_cycles: u64) -> Self {
        self.context_builder.max_cycles(max_cycles);
        self
    }

    /// Whether to skip deferred proof verification in the executor.
    ///
    /// # Arguments
    /// * `value` - Whether to skip deferred proof verification.
    ///
    /// # Details
    /// If set to `true`, the executor will skip the deferred proof verification step. This is useful
    /// for reducing the execution time of the program and optimistically assuming that the
    /// deferred proofs are correct.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin, include_elf, Prover};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let builder = client.execute(elf, &stdin)
    ///     .deferred_proof_verification(false)
    ///     .run();
    /// ```
    #[must_use]
    pub fn deferred_proof_verification(mut self, value: bool) -> Self {
        self.context_builder.set_skip_deferred_proof_verification(!value);
        self
    }

    /// Executes the program on the input with the built arguments.
    ///
    /// # Details
    /// This method will execute the program on the input with the built arguments. If the program
    /// fails to execute, the method will return an error.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin, include_elf, Prover};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let (public_values, execution_report) = client.execute(elf, &stdin)
    ///     .run()
    ///     .unwrap();
    /// ```
    pub fn run(self) -> Result<(SP1PublicValues, ExecutionReport)> {
        let Self { prover, elf, stdin, mut context_builder } = self;
        let context = context_builder.build();
        Ok(prover.execute(elf, &stdin, context)?)
    }
}
