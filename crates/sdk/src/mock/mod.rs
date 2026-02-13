//! # Mock Prover
//!
//! A mock prover that can be used for testing.

pub mod builder;

use std::pin::Pin;

use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{
    worker::{SP1LightNode, SP1NodeCore},
    Groth16Bn254Proof, PlonkBn254Proof, SP1VerifyingKey,
};

use crate::{
    proof::verify_mock_public_inputs,
    prover::{BaseProveRequest, ProveRequest},
    Prover, SP1Proof, SP1ProofWithPublicValues, SP1ProvingKey, SP1VerificationError, StatusCode,
};
use sp1_core_executor::SP1CoreOpts;
use std::future::{Future, IntoFuture};

/// A mock prover that can be used for testing.
#[derive(Clone)]
pub struct MockProver {
    inner: SP1LightNode,
}

impl MockProver {
    /// Create a new mock prover.
    #[must_use]
    pub async fn new() -> Self {
        tracing::info!("initializing mock prover");
        Self { inner: SP1LightNode::new().await }
    }

    /// Create a new mock prover with custom options.
    #[must_use]
    pub async fn new_with_opts(opts: SP1CoreOpts) -> Self {
        Self { inner: SP1LightNode::with_opts(opts).await }
    }
}

impl Prover for MockProver {
    type ProvingKey = SP1ProvingKey;

    type Error = anyhow::Error;

    type ProveRequest<'a> = MockProveRequest<'a>;

    fn inner(&self) -> &SP1NodeCore {
        self.inner.inner()
    }

    fn prove<'a>(&'a self, pk: &'a Self::ProvingKey, stdin: SP1Stdin) -> Self::ProveRequest<'a> {
        MockProveRequest { base: BaseProveRequest::new(self, pk, stdin) }
    }

    fn setup(
        &self,
        elf: sp1_build::Elf,
    ) -> impl crate::prover::SendFutureResult<Self::ProvingKey, Self::Error> {
        async move {
            let vk = self.inner.setup(&elf).await?;
            let pk = SP1ProvingKey { vk, elf };
            Ok(pk)
        }
    }

    fn verify(
        &self,
        proof: &SP1ProofWithPublicValues,
        vkey: &SP1VerifyingKey,
        _status_code: Option<StatusCode>,
    ) -> Result<(), SP1VerificationError> {
        match &proof.proof {
            SP1Proof::Plonk(PlonkBn254Proof { public_inputs, .. }) => {
                // Verify the mock Plonk proof by checking public inputs match.
                // For mock proofs, the encoded_proof is empty, so we only verify the public inputs.
                verify_mock_public_inputs(vkey, &proof.public_values, public_inputs)
                    .map_err(SP1VerificationError::Plonk)
            }
            SP1Proof::Groth16(Groth16Bn254Proof { public_inputs, .. }) => {
                // Verify the mock Groth16 proof by checking public inputs match.
                // For mock proofs, the encoded_proof is empty, so we only verify the public inputs.
                verify_mock_public_inputs(vkey, &proof.public_values, public_inputs)
                    .map_err(SP1VerificationError::Groth16)
            }
            _ => Ok(()),
        }
    }
}

/// A mock prove request that can be used for testing.
pub struct MockProveRequest<'a> {
    pub(crate) base: BaseProveRequest<'a, MockProver>,
}

impl<'a> ProveRequest<'a, MockProver> for MockProveRequest<'a> {
    fn base(&mut self) -> &mut BaseProveRequest<'a, MockProver> {
        &mut self.base
    }
}

impl<'a> IntoFuture for MockProveRequest<'a> {
    type Output = Result<SP1ProofWithPublicValues, anyhow::Error>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let BaseProveRequest { prover, pk, mode, stdin, context_builder } = self.base;
            tracing::info!(mode = ?mode, "generating mock proof");

            // Override the context builder, in case there's anything added.
            let mut req = prover.execute(pk.elf.clone(), stdin);
            req.context_builder = context_builder;

            // Spawn blocking under the hood.
            let (public_values, _) = req.await?;

            Ok(SP1ProofWithPublicValues::create_mock_proof(
                &pk.vk,
                public_values,
                mode,
                prover.version(),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{prover::ProveRequest, utils::setup_logger, MockProver, Prover, SP1Stdin};

    /// Test mock proof creation and verification for all proof types.
    #[tokio::test]
    async fn test_mock_proof_all_types() {
        setup_logger();
        let prover = MockProver::new().await;
        let pk =
            prover.setup(test_artifacts::FIBONACCI_ELF).await.expect("failed to setup proving key");

        // Test Core proof.
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let core_proof =
            prover.prove(&pk, stdin).core().await.expect("failed to create mock Core proof");
        prover.verify(&core_proof, &pk.vk, None).expect("failed to verify mock Core proof");

        // Test Compressed proof.
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let compressed_proof = prover
            .prove(&pk, stdin)
            .compressed()
            .await
            .expect("failed to create mock Compressed proof");
        prover
            .verify(&compressed_proof, &pk.vk, None)
            .expect("failed to verify mock Compressed proof");

        // Test Plonk proof.
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let plonk_proof =
            prover.prove(&pk, stdin).plonk().await.expect("failed to create mock Plonk proof");
        prover.verify(&plonk_proof, &pk.vk, None).expect("failed to verify mock Plonk proof");

        // Test Groth16 proof.
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let groth16_proof =
            prover.prove(&pk, stdin).groth16().await.expect("failed to create mock Groth16 proof");
        prover.verify(&groth16_proof, &pk.vk, None).expect("failed to verify mock Groth16 proof");
    }

    /// Test that mock proofs have correct public values.
    #[tokio::test]
    async fn test_mock_proof_public_values() {
        setup_logger();
        let prover = MockProver::new().await;
        let pk =
            prover.setup(test_artifacts::FIBONACCI_ELF).await.expect("failed to setup proving key");
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);

        // Execute first to get expected public values.
        let (expected_pv, _) =
            prover.execute(pk.elf.clone(), stdin.clone()).await.expect("failed to execute program");

        // Create a mock core proof.
        let proof =
            prover.prove(&pk, stdin).core().await.expect("failed to create mock Core proof");

        // Verify public values match.
        assert_eq!(proof.public_values.as_slice(), expected_pv.as_slice());
    }

    /// Test that mock Plonk proof verification fails with wrong vkey.
    #[tokio::test]
    async fn test_mock_plonk_proof_wrong_vkey_fails() {
        setup_logger();
        let prover = MockProver::new().await;

        // Setup two different programs.
        let pk1 = prover
            .setup(test_artifacts::FIBONACCI_ELF)
            .await
            .expect("failed to setup proving key 1");
        let pk2 = prover
            .setup(test_artifacts::HELLO_WORLD_ELF)
            .await
            .expect("failed to setup proving key 2");

        // Create a Plonk proof with pk1.
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let proof =
            prover.prove(&pk1, stdin).plonk().await.expect("failed to create mock Plonk proof");

        // Verification with pk2's vkey should fail.
        let result = prover.verify(&proof, &pk2.vk, None);
        assert!(result.is_err(), "Verification should fail with wrong vkey");
    }

    /// Test that mock Groth16 proof verification fails with wrong vkey.
    #[tokio::test]
    async fn test_mock_groth16_proof_wrong_vkey_fails() {
        setup_logger();
        let prover = MockProver::new().await;

        // Setup two different programs.
        let pk1 = prover
            .setup(test_artifacts::FIBONACCI_ELF)
            .await
            .expect("failed to setup proving key 1");
        let pk2 = prover
            .setup(test_artifacts::HELLO_WORLD_ELF)
            .await
            .expect("failed to setup proving key 2");

        // Create a Groth16 proof with pk1.
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let proof =
            prover.prove(&pk1, stdin).groth16().await.expect("failed to create mock Groth16 proof");

        // Verification with pk2's vkey should fail.
        let result = prover.verify(&proof, &pk2.vk, None);
        assert!(result.is_err(), "Verification should fail with wrong vkey");
    }

    /// Test that mock Plonk proof verification fails with tampered public values.
    #[tokio::test]
    async fn test_mock_plonk_proof_tampered_public_values_fails() {
        setup_logger();
        let prover = MockProver::new().await;
        let pk =
            prover.setup(test_artifacts::FIBONACCI_ELF).await.expect("failed to setup proving key");

        // Create a Plonk proof.
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let mut proof =
            prover.prove(&pk, stdin).plonk().await.expect("failed to create mock Plonk proof");

        // Tamper with public values.
        proof.public_values = sp1_primitives::io::SP1PublicValues::from(&[0xDE, 0xAD, 0xBE, 0xEF]);

        // Verification should fail because public_values hash won't match.
        let result = prover.verify(&proof, &pk.vk, None);
        assert!(result.is_err(), "Verification should fail with tampered public values");
    }

    /// Test that mock Groth16 proof verification fails with tampered public values.
    #[tokio::test]
    async fn test_mock_groth16_proof_tampered_public_values_fails() {
        setup_logger();
        let prover = MockProver::new().await;
        let pk =
            prover.setup(test_artifacts::FIBONACCI_ELF).await.expect("failed to setup proving key");

        // Create a Groth16 proof.
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let mut proof =
            prover.prove(&pk, stdin).groth16().await.expect("failed to create mock Groth16 proof");

        // Tamper with public values.
        proof.public_values = sp1_primitives::io::SP1PublicValues::from(&[0xDE, 0xAD, 0xBE, 0xEF]);

        // Verification should fail because public_values hash won't match.
        let result = prover.verify(&proof, &pk.vk, None);
        assert!(result.is_err(), "Verification should fail with tampered public values");
    }
}
