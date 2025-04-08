//! # CPU Prover Builder
//!
//! This module provides a builder for the [`CpuProver`].

use sp1_prover::SP1Prover;

use super::CudaProver;

/// A builder for the [`CudaProver`].
///
/// The builder is used to configure the [`CudaProver`] before it is built.
#[derive(Debug, Default)]
pub struct CudaProverBuilder {
    moongate_endpoint: Option<String>,
}

impl CudaProverBuilder {
    /// Sets the Moongate server endpoint.
    ///
    /// # Details
    /// Run the CUDA prover with the provided endpoint for the Moongate (GPU prover) server.
    /// Enables more customization and avoids `DinD` configurations.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let prover = ProverClient::builder().cuda().with_moongate_endpoint("http://...").build();
    /// ```
    #[must_use]
    pub fn with_moongate_endpoint(mut self, endpoint: &str) -> Self {
        self.moongate_endpoint = Some(endpoint.to_string());
        self
    }

    /// Builds a [`CudaProver`].
    ///
    /// # Details
    /// This method will build a [`CudaProver`] with the given parameters. In particular, it will
    /// build a mock prover if the `mock` flag is set.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let prover = ProverClient::builder().cuda().build();
    /// ```
    #[must_use]
    pub fn build(self) -> CudaProver {
        CudaProver::new(SP1Prover::new(), self.moongate_endpoint)
    }
}
