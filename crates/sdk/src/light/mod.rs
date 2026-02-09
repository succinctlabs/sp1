//! # Light Prover
//!
//! A lightweight prover that only executes and verifies but does not generate proofs.
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

/// A lightweight prover that only executes and verifies but does not generate proofs.
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
            Err(anyhow::anyhow!(
                "Use LightProver for executing and verifying only. For proving, use CpuProver"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{prover::ProveRequest, utils::setup_logger, LightProver, Prover, SP1Stdin};

    /// Test that execute works and prove errors.
    #[tokio::test]
    async fn test_light_execute_and_prove() {
        setup_logger();
        let prover = LightProver::new().await;
        let pk =
            prover.setup(test_artifacts::FIBONACCI_ELF).await.expect("failed to setup proving key");

        // Execute should succeed.
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let (pv, _) =
            prover.execute(pk.elf.clone(), stdin).await.expect("failed to execute program");
        assert!(!pv.as_slice().is_empty());

        // Prove should error.
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let result = prover.prove(&pk, stdin).core().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("executing and verifying only"));
    }
}
