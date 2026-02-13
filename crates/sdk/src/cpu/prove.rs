//! # CPU Proving
//!
//! This module provides a builder for proving a program on the CPU.

use std::{
    future::{Future, IntoFuture},
    pin::Pin,
};

use anyhow::Result;
// use sp1_core_executor::IoWriter;
use sp1_core_machine::io::SP1Stdin;

use super::{CPUProverError, CpuProver};
use crate::{
    prover::{BaseProveRequest, ProveRequest},
    utils::proof_mode,
    SP1ProofWithPublicValues, SP1ProvingKey,
};

/// A builder for proving a program on the CPU.
///
/// This builder provides a typed interface for configuring the SP1 RISC-V prover. The builder is
/// used for only the [`crate::cpu::CpuProver`] client type.
pub struct CpuProveBuilder<'a> {
    pub(crate) base: BaseProveRequest<'a, CpuProver>,
}

impl<'a> CpuProveBuilder<'a> {
    pub(super) const fn new(prover: &'a CpuProver, pk: &'a SP1ProvingKey, stdin: SP1Stdin) -> Self {
        Self { base: BaseProveRequest::new(prover, pk, stdin) }
    }

    // todo!(n): add stdout/stderr pipes here.
    // /// Override the default stdout of the guest program.
    // ///
    // /// # Example
    // /// ```rust,no_run
    // /// use sp1_sdk::{include_elf, Prover, ProverClient, SP1Stdin};
    // ///
    // /// let mut stdout = Vec::new();
    // ///
    // /// let elf = &[1, 2, 3];
    // /// let stdin = SP1Stdin::new();
    // ///
    // /// let client = ProverClient::builder().cpu().build();
    // /// client.execute(elf, &stdin).stdout(&mut stdout).run();
    // /// ```
    // #[must_use]
    // pub fn stdout<W: IoWriter>(mut self, writer: &'static mut W) -> Self {
    //     self.context_builder.stdout(writer);
    //     self
    // }

    // /// Override the default stdout of the guest program.
    // ///
    // /// # Example
    // /// ```rust,no_run
    // /// use sp1_sdk::{include_elf, Prover, ProverClient, SP1Stdin};
    // ///
    // /// let mut stderr = Vec::new();
    // ///
    // /// let elf = &[1, 2, 3];
    // /// let stdin = SP1Stdin::new();
    // ///
    // /// let client = ProverClient::builder().cpu().build();
    // /// client.execute(elf, &stdin).stderr(&mut stderr).run();
    // /// ```````
    // #[must_use]
    // pub fn stderr<W: IoWriter>(mut self, writer: &'static mut W) -> Self {
    //     self.context_builder.stderr(writer);
    //     self
    // }

    /// Run the prover with the built arguments.
    ///
    /// # Details
    /// This method will run the prover with the built arguments. If the prover fails to run, the
    /// method will return an error.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().cpu().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let proof = client.prove(&pk, stdin).await.unwrap();
    /// });
    /// ```
    async fn run(self) -> Result<SP1ProofWithPublicValues, CPUProverError> {
        // Get the arguments.
        let BaseProveRequest { prover, pk, stdin, mode, mut context_builder } = self.base;

        // Dump the program and stdin to files for debugging if `SP1_DUMP` is set.
        crate::utils::sp1_dump(&pk.elf, &stdin);

        tracing::info!(mode = ?mode, "starting proof generation");
        let context = context_builder.build();
        Ok(prover.prover.prove_with_mode(&pk.elf, stdin, context, proof_mode(mode)).await?.into())
    }
}

impl<'a> ProveRequest<'a, CpuProver> for CpuProveBuilder<'a> {
    fn base(&mut self) -> &mut BaseProveRequest<'a, CpuProver> {
        &mut self.base
    }
}

impl<'a> IntoFuture for CpuProveBuilder<'a> {
    type Output = Result<SP1ProofWithPublicValues, CPUProverError>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.run())
    }
}
