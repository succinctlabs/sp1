//! # CPU Proving
//!
//! This module provides a builder for proving a program on the CPU.

use anyhow::Result;
// use sp1_core_executor::IoWriter;
use sp1_core_machine::io::SP1Stdin;

use super::{CPUProverError, CpuProver};
use crate::{
    blocking::{
        block_on,
        prover::{BaseProveRequest, ProveRequest},
    },
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
}

impl<'a> ProveRequest<'a, CpuProver> for CpuProveBuilder<'a> {
    fn base(&mut self) -> &mut BaseProveRequest<'a, CpuProver> {
        &mut self.base
    }

    /// Run the prover with the built arguments.
    ///
    /// # Details
    /// This method will run the prover with the built arguments. If the prover fails to run, the
    /// method will return an error.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::blocking::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// let elf = Elf::Static(&[1, 2, 3]);
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let pk = client.setup(elf).unwrap();
    /// let proof = client.prove(&pk, stdin).run().unwrap();
    /// ```
    fn run(self) -> Result<SP1ProofWithPublicValues, CPUProverError> {
        // Get the arguments.
        let BaseProveRequest { prover, pk, stdin, mode, mut context_builder } = self.base;

        // Dump the program and stdin to files for debugging if `SP1_DUMP` is set.
        crate::utils::sp1_dump(&pk.elf, &stdin);

        tracing::info!(mode = ?mode, "starting proof generation");
        let context = context_builder.build();
        Ok(block_on(prover.prover.prove_with_mode(&pk.elf, stdin, context, proof_mode(mode)))?
            .into())
    }
}
