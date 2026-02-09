//! # Light Prover (Blocking)
//!
//! A lightweight blocking prover that generates mock proofs but performs real verification.

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

/// A lightweight blocking prover that generates mock proofs but performs real verification.
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
        let BaseProveRequest { prover, pk, mode, stdin, context_builder } = self.base;
        tracing::info!(mode = ?mode, "generating mock proof (light)");
        let mut req = prover.execute(pk.elf.clone(), stdin);
        req.context_builder = context_builder;
        let (public_values, _) = req.run()?;
        Ok(SP1ProofWithPublicValues::create_mock_proof(
            &pk.vk,
            public_values,
            mode,
            prover.version(),
        ))
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

    /// Test that the light prover can generate mock proofs.
    #[test]
    fn test_light_proof_generation() {
        setup_logger();
        let prover = LightProver::new();
        let pk = prover.setup(test_artifacts::FIBONACCI_ELF).expect("failed to setup proving key");

        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let core_proof =
            prover.prove(&pk, stdin).core().run().expect("failed to create light Core proof");

        // Light prover uses real verification, which will fail on mock proofs.
        assert!(prover.verify(&core_proof, &pk.vk, None).is_err());
    }

    /// Test that light proofs have correct public values.
    #[test]
    fn test_light_proof_public_values() {
        setup_logger();
        let prover = LightProver::new();
        let pk = prover.setup(test_artifacts::FIBONACCI_ELF).expect("failed to setup proving key");
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);

        let (expected_pv, _) =
            prover.execute(pk.elf.clone(), stdin.clone()).run().expect("failed to execute program");

        let proof =
            prover.prove(&pk, stdin).core().run().expect("failed to create light Core proof");

        assert_eq!(proof.public_values.as_slice(), expected_pv.as_slice());
    }

    /// Test that builder syntax works: ProverClient::builder().light().build()
    #[test]
    fn test_light_builder() {
        setup_logger();
        let prover = crate::blocking::ProverClient::builder().light().build();
        let pk = prover.setup(test_artifacts::FIBONACCI_ELF).expect("failed to setup proving key");
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let _proof =
            prover.prove(&pk, stdin).core().run().expect("failed to create light Core proof");
    }
}
