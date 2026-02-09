//! # Light Prover
//!
//! A lightweight prover that generates mock proofs but performs real verification.
//!
//! Unlike [`MockProver`](crate::MockProver), the light prover uses the default
//! [`Prover::verify`](crate::Prover::verify) implementation which does full cryptographic
//! proof verification. This makes it useful as a lightweight verifier node that can
//! validate proofs produced by other provers (CPU, CUDA, network).

pub mod builder;

use std::pin::Pin;

use sp1_core_executor::SP1CoreOpts;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::worker::{SP1LightNode, SP1NodeCore};

use crate::{
    prover::{BaseProveRequest, ProveRequest},
    Prover, SP1ProofWithPublicValues, SP1ProvingKey,
};
use std::future::{Future, IntoFuture};

/// A lightweight prover that generates mock proofs but performs real verification.
#[derive(Clone)]
pub struct LightProver {
    inner: SP1LightNode,
}

impl LightProver {
    /// Create a new light prover.
    #[must_use]
    pub async fn new() -> Self {
        tracing::info!("initializing light prover");
        Self { inner: SP1LightNode::new().await }
    }

    /// Create a new light prover with custom options.
    #[must_use]
    pub async fn new_with_opts(opts: SP1CoreOpts) -> Self {
        Self { inner: SP1LightNode::with_opts(opts).await }
    }
}

impl Prover for LightProver {
    type ProvingKey = SP1ProvingKey;

    type Error = anyhow::Error;

    type ProveRequest<'a> = LightProveRequest<'a>;

    fn inner(&self) -> &SP1NodeCore {
        self.inner.inner()
    }

    fn prove<'a>(&'a self, pk: &'a Self::ProvingKey, stdin: SP1Stdin) -> Self::ProveRequest<'a> {
        LightProveRequest { base: BaseProveRequest::new(self, pk, stdin) }
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
}

impl<'a> IntoFuture for LightProveRequest<'a> {
    type Output = Result<SP1ProofWithPublicValues, anyhow::Error>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let BaseProveRequest { prover, pk, mode, stdin, context_builder } = self.base;
            tracing::info!(mode = ?mode, "generating mock proof (light)");

            let mut req = prover.execute(pk.elf.clone(), stdin);
            req.context_builder = context_builder;

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
    use crate::{prover::ProveRequest, utils::setup_logger, LightProver, Prover, SP1Stdin};

    /// Test that the light prover can generate mock proofs for all proof types.
    #[tokio::test]
    async fn test_light_proof_all_types() {
        setup_logger();
        let prover = LightProver::new().await;
        let pk =
            prover.setup(test_artifacts::FIBONACCI_ELF).await.expect("failed to setup proving key");

        // Test Core proof.
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let core_proof =
            prover.prove(&pk, stdin).core().await.expect("failed to create light Core proof");
        // Light prover uses real verification, which will fail on mock proofs.
        assert!(prover.verify(&core_proof, &pk.vk, None).is_err());

        // Test Compressed proof.
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let compressed_proof = prover
            .prove(&pk, stdin)
            .compressed()
            .await
            .expect("failed to create light Compressed proof");
        assert!(prover.verify(&compressed_proof, &pk.vk, None).is_err());

        // Test Plonk proof.
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let plonk_proof =
            prover.prove(&pk, stdin).plonk().await.expect("failed to create light Plonk proof");
        assert!(prover.verify(&plonk_proof, &pk.vk, None).is_err());

        // Test Groth16 proof.
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let groth16_proof = prover
            .prove(&pk, stdin)
            .groth16()
            .await
            .expect("failed to create light Groth16 proof");
        assert!(prover.verify(&groth16_proof, &pk.vk, None).is_err());
    }

    /// Test that light proofs have correct public values.
    #[tokio::test]
    async fn test_light_proof_public_values() {
        setup_logger();
        let prover = LightProver::new().await;
        let pk =
            prover.setup(test_artifacts::FIBONACCI_ELF).await.expect("failed to setup proving key");
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);

        // Execute first to get expected public values.
        let (expected_pv, _) =
            prover.execute(pk.elf.clone(), stdin.clone()).await.expect("failed to execute program");

        // Create a light core proof.
        let proof =
            prover.prove(&pk, stdin).core().await.expect("failed to create light Core proof");

        // Verify public values match.
        assert_eq!(proof.public_values.as_slice(), expected_pv.as_slice());
    }

    /// Test that builder syntax works: ProverClient::builder().light().build().await
    #[tokio::test]
    async fn test_light_builder() {
        setup_logger();
        let prover = crate::ProverClient::builder().light().build().await;
        let pk =
            prover.setup(test_artifacts::FIBONACCI_ELF).await.expect("failed to setup proving key");
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let _proof =
            prover.prove(&pk, stdin).core().await.expect("failed to create light Core proof");
    }
}
