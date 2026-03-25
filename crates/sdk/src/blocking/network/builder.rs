//! # Network Prover Builder (Blocking)
//!
//! This module provides a blocking builder for the [`NetworkProver`].

use alloy_primitives::Address;

use super::NetworkProver;
use crate::network::{signer::NetworkSigner, NetworkMode, TEE_NETWORK_RPC_URL};

/// A builder for the blocking [`NetworkProver`].
///
/// The builder is used to configure the [`NetworkProver`] before it is built.
#[derive(Default)]
pub struct NetworkProverBuilder {
    pub(crate) private_key: Option<String>,
    pub(crate) rpc_url: Option<String>,
    pub(crate) tee_signers: Option<Vec<Address>>,
    pub(crate) signer: Option<NetworkSigner>,
    pub(crate) network_mode: Option<NetworkMode>,
}

impl NetworkProverBuilder {
    /// Creates a new [`NetworkProverBuilder`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            private_key: None,
            rpc_url: None,
            tee_signers: None,
            signer: None,
            network_mode: None,
        }
    }

    /// Sets the Secp256k1 private key (same format as the one used by Ethereum).
    ///
    /// # Details
    /// Sets the private key that will be used sign requests sent to the network. By default, the
    /// private key is read from the `NETWORK_PRIVATE_KEY` environment variable.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::blocking::ProverClient;
    ///
    /// let prover = ProverClient::builder().network().private_key("...").build();
    /// ```
    #[must_use]
    pub fn private_key(mut self, private_key: &str) -> Self {
        self.private_key = Some(private_key.to_string());
        self
    }

    /// Sets the remote procedure call URL.
    ///
    /// # Details
    /// The URL determines the network that the client will connect to. By default, the URL is
    /// read from the `NETWORK_RPC_URL` environment variable.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::blocking::ProverClient;
    ///
    /// let prover = ProverClient::builder().network().rpc_url("...").build();
    /// ```
    #[must_use]
    pub fn rpc_url(mut self, rpc_url: &str) -> Self {
        self.rpc_url = Some(rpc_url.to_string());
        self
    }

    /// Process proofs inside a TEE.
    ///
    /// # Details
    /// In order to keep the inputs private, it is possible to route the proof
    /// requests to a TEE enclave.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::blocking::ProverClient;
    ///
    /// let prover = ProverClient::builder().network().private().build();
    /// ```
    #[must_use]
    pub fn private(mut self) -> Self {
        self.rpc_url = Some(TEE_NETWORK_RPC_URL.to_string());
        self
    }

    /// Sets the list of TEE signers, used for verifying TEE proofs.
    #[must_use]
    pub fn tee_signers(mut self, tee_signers: &[Address]) -> Self {
        self.tee_signers = Some(tee_signers.to_vec());
        self
    }

    /// Sets the network signer to use for signing requests.
    ///
    /// # Details
    /// This method allows you to provide a custom signer implementation, such as AWS KMS or
    /// a local private key signer. If both `signer` and `private_key` are provided, the signer
    /// takes precedence.
    #[must_use]
    pub fn signer(mut self, signer: NetworkSigner) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Builds a blocking [`NetworkProver`].
    ///
    /// # Details
    /// This method will build a [`NetworkProver`] with the given parameters. If `signer` is
    /// provided, it will be used directly. Otherwise, if `private_key` is provided, a local
    /// signer will be created from it. If neither is provided, the method will look for the
    /// `NETWORK_PRIVATE_KEY` environment variable.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::blocking::ProverClient;
    ///
    /// let prover = ProverClient::builder().network().private_key("...").build();
    /// ```
    #[must_use]
    pub fn build(self) -> NetworkProver {
        let async_builder = crate::network::builder::NetworkProverBuilder {
            private_key: self.private_key,
            rpc_url: self.rpc_url,
            tee_signers: self.tee_signers,
            signer: self.signer,
            network_mode: self.network_mode,
        };
        let prover = crate::blocking::block_on(async_builder.build());
        NetworkProver { prover }
    }
}
