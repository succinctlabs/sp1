//! # Mock Prover Builder
//!
//! This module provides a builder for the blocking [`MockProver`].

use super::MockProver;
use sp1_core_executor::SP1CoreOpts;
use sp1_core_machine::riscv::RiscvAir;
use sp1_hypercube::Machine;
use sp1_primitives::SP1Field;
use sp1_prover::worker::SP1LightNode;

use crate::blocking::block_on;

/// A builder for the blocking [`MockProver`].
pub struct MockProverBuilder {
    /// Optional core options to configure the prover.
    core_opts: Option<SP1CoreOpts>,
    /// The machine
    machine: Machine<SP1Field, RiscvAir<SP1Field>>,
}

impl Default for MockProverBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MockProverBuilder {
    /// Creates a new [`MockProverBuilder`] with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_machine(RiscvAir::machine())
    }

    /// Creates a new [`MockProverBuilder`] with a given machine.
    #[must_use]
    pub const fn new_with_machine(machine: Machine<SP1Field, RiscvAir<SP1Field>>) -> Self {
        Self { core_opts: None, machine }
    }

    /// Sets the core options for the prover.
    #[must_use]
    pub fn core_opts(mut self, opts: SP1CoreOpts) -> Self {
        self.core_opts = Some(opts);
        self
    }

    /// Sets the core options for the prover (alias for `core_opts`).
    #[must_use]
    pub fn with_opts(self, opts: SP1CoreOpts) -> Self {
        self.core_opts(opts)
    }

    /// Builds a blocking [`MockProver`].
    #[must_use]
    pub fn build(self) -> MockProver {
        tracing::info!("initializing mock prover");
        let node = match self.core_opts {
            Some(opts) => block_on(SP1LightNode::with_opts_and_machine(self.machine, opts)),
            None => block_on(SP1LightNode::new_with_machine(self.machine)),
        };
        MockProver::from_node(node)
    }
}
