//! # Light Prover (Blocking)
//!
//! A lightweight blocking prover that only executes and verifies but does not generate proofs.

pub mod builder;

use sp1_core_machine::io::SP1Stdin;
use sp1_prover::worker::{SP1LightNode, SP1NodeCore};

use crate::{
    blocking::{
        block_on,
        cpu::CPUProverError,
        prover::{BaseProveRequest, ProveRequest, Prover},
    },
    SP1ProofWithPublicValues, SP1ProvingKey,
};

/// A lightweight blocking prover that only executes and verifies but does not generate proofs.
#[derive(Clone)]
pub struct LightProver {
    inner: SP1LightNode,
}

impl Default for LightProver {
    fn default() -> Self {
        tracing::info!("initializing light prover");
        let node = block_on(SP1LightNode::new());
        Self { inner: node }
    }
}

impl LightProver {
    /// Create a new light prover.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a light prover from an existing light node.
    pub(crate) fn from_node(inner: SP1LightNode) -> Self {
        Self { inner }
    }
}

impl Prover for LightProver {
    type ProvingKey = SP1ProvingKey;

    type Error = CPUProverError;

    type ProveRequest<'a> = LightProveRequest<'a>;

    fn inner(&self) -> &SP1NodeCore {
        self.inner.inner()
    }

    fn prove<'a>(&'a self, pk: &'a Self::ProvingKey, stdin: SP1Stdin) -> Self::ProveRequest<'a> {
        LightProveRequest { base: BaseProveRequest::new(self, pk, stdin) }
    }

    fn setup(&self, elf: sp1_build::Elf) -> Result<Self::ProvingKey, Self::Error> {
        let vk = block_on(self.inner.setup(&elf))?;
        Ok(SP1ProvingKey { vk, elf })
    }

    // verify() is intentionally NOT overridden here.
    // The default Prover::verify performs real cryptographic verification,
    // unlike MockProver which only checks public value hashes.
}

/// A light prove request.
pub struct LightProveRequest<'a> {
    pub(crate) base: BaseProveRequest<'a, LightProver>,
}

impl<'a> ProveRequest<'a, LightProver> for LightProveRequest<'a> {
    fn base(&mut self) -> &mut BaseProveRequest<'a, LightProver> {
        &mut self.base
    }

    fn run(self) -> Result<SP1ProofWithPublicValues, CPUProverError> {
        Err(CPUProverError::Unexpected(anyhow::anyhow!(
            "Use LightProver for executing and verifying only. For proving, use CpuProver"
        )))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        blocking::prover::{ProveRequest, Prover},
        utils::setup_logger,
        SP1Stdin,
    };

    use super::LightProver;

    /// Test that execute works and prove errors.
    #[test]
    fn test_light_execute_and_prove() {
        setup_logger();
        let prover = LightProver::new();
        let pk = prover.setup(test_artifacts::FIBONACCI_ELF).expect("failed to setup proving key");

        // Execute should succeed.
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let (pv, _) = prover.execute(pk.elf.clone(), stdin).run().expect("failed to execute");
        assert!(!pv.as_slice().is_empty());

        // Prove should error.
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let result = prover.prove(&pk, stdin).core().run();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("executing and verifying only"));
    }
}
