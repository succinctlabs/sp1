//! # CPU Prover Builder
//!
//! This module provides a builder for the [`CpuProver`].

use sp1_cuda::MoongateServer;
use sp1_prover::SP1Prover;

use super::CudaProver;

/// A builder for the [`CudaProver`].
///
/// The builder is used to configure the [`CudaProver`] before it is built.
#[derive(Debug, Default)]
pub struct CudaProverBuilder {
    moongate_server: Option<MoongateServer>,
}

impl CudaProverBuilder {
    /// Uses an external Moongate server with the provided endpoint.
    ///
    /// # Details
    /// Run the CUDA prover with the provided endpoint for the Moongate (GPU prover) server.
    /// Enables more customization and avoids `DinD` configurations.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let prover = ProverClient::builder().cuda().server("http://...").build();
    /// ```
    #[must_use]
    pub fn server(self, endpoint: &str) -> ExternalMoongateServerCudaProverBuilder {
        ExternalMoongateServerCudaProverBuilder { endpoint: endpoint.to_string() }
    }

    /// Allows to customize the embedded Moongate server.
    ///
    /// # Details
    /// The builder returned by this method allow to customize the embedded Moongate server port and
    /// visible device. It is therefore possible to instantiate multiple [`CudaProver`s], each one
    /// linked to a different GPU.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let prover = ProverClient::builder().cuda().local().port(3200).build();
    /// ```
    #[must_use]
    pub fn local(self) -> LocalMoongateServerCudaProverBuilder {
        LocalMoongateServerCudaProverBuilder::default()
    }

    /// Builds a [`CudaProver`].
    ///
    /// # Details
    /// This method will build a [`CudaProver`] with the given parameters.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let prover = ProverClient::builder().cuda().build();
    /// ```
    #[must_use]
    pub fn build(self) -> CudaProver {
        CudaProver::new(SP1Prover::new(), self.moongate_server.unwrap_or_default())
    }
}

/// A builder for the [`CudaProver`] with an external Moongate server.
///
/// This is not meant to be used directly. Use [`CudaProverBuilder::server`]
/// instead.
#[derive(Debug)]
pub struct ExternalMoongateServerCudaProverBuilder {
    endpoint: String,
}

impl ExternalMoongateServerCudaProverBuilder {
    /// Builds a [`CudaProver`].
    ///
    /// # Details
    /// This method will build a [`CudaProver`] with the given parameters.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let prover = ProverClient::builder().cuda().server("http://...").build();
    /// ```
    #[must_use]
    pub fn build(self) -> CudaProver {
        CudaProver::new(SP1Prover::new(), MoongateServer::External { endpoint: self.endpoint })
    }
}

/// A builder for the [`CudaProver`] with the embedded Moongate server.
///
/// This is not meant to be used directly. Use [`CudaProverBuilder::local`]
/// instead.
#[derive(Debug, Default)]
pub struct LocalMoongateServerCudaProverBuilder {
    visible_device_index: Option<u64>,
    port: Option<u64>,
}

impl LocalMoongateServerCudaProverBuilder {
    /// Sets the embedded Moongate server port.
    ///
    /// If not set, the default value is `3000`.
    #[must_use]
    pub fn port(mut self, port: u64) -> Self {
        self.port = Some(port);
        self
    }

    /// Sets the embedded Moongate visible device index.
    ///
    /// If not set, the default value is `3000`.
    #[must_use]
    pub fn visible_device(mut self, index: u64) -> Self {
        self.visible_device_index = Some(index);
        self
    }

    /// Builds a [`CudaProver`].
    ///
    /// # Details
    /// This method will build a [`CudaProver`] with the given parameters.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let prover = ProverClient::builder().cuda().local().visible_device(2).port(3002).build();
    /// ```
    #[must_use]
    pub fn build(self) -> CudaProver {
        CudaProver::new(
            SP1Prover::new(),
            MoongateServer::Local {
                visible_device_index: self.visible_device_index,
                port: self.port,
            },
        )
    }
}
