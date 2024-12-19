//! # Network Prover Builder
//!
//! This module provides a builder for the [NetworkProver].

use crate::NetworkProver;

/// A builder for the [NetworkProver].
///
/// The builder is used to configure the [NetworkProver] before it is built.
pub struct NetworkProverBuilder {
    pub(crate) private_key: Option<String>,
    pub(crate) rpc_url: Option<String>,
}

impl NetworkProverBuilder {
    /// Sets the Secp256k1 private key (same format as the one used by Ethereum).
    ///
    /// # Details
    /// Sets the private key that will be used sign requests sent to the network. By default, the
    /// private key is read from the `SUCCINCT_PRIVATE_KEY` environment variable.
    ///
    /// # Example
    /// ```rust,no_run
    /// let prover = ProverClient::network()
    ///     .private_key("...")
    ///     .build();
    /// ```
    pub fn private_key(mut self, private_key: String) -> Self {
        self.private_key = Some(private_key);
        self
    }

    /// Sets the remote procedure call URL.
    ///
    /// # Details
    /// The URL determintes the network that the client will connect to. By default, the URL is
    /// read from the `SUCCINCT_RPC_URL` environment variable.
    ///
    /// # Example
    /// ```rust,no_run
    /// let prover = ProverClient::network()
    ///     .rpc_url("...")
    ///     .build();
    /// ```
    pub fn rpc_url(mut self, rpc_url: String) -> Self {
        self.rpc_url = Some(rpc_url);
        self
    }

    /// Builds a [NetworkProver].
    ///
    /// # Details
    /// This method will build a [NetworkProver] with the given parameters. If the private key is
    /// not provided, the method will look for the `SP1_PRIVATE_KEY` environment variable.
    ///
    /// # Example
    /// ```rust,no_run
    /// let prover = ProverClient::network()
    ///     .private_key("...")
    ///     .rpc_url("...")
    ///     .build();
    /// ```
    pub fn build(self) -> NetworkProver {
        let private_key = match self.private_key {
            Some(private_key) => private_key,
            None => std::env::var("NETWORK_PRIVATE_KEY").expect(
                "NETWORK_PRIVATE_KEY environment variable is not set. \
                Please set it to your private key or use the .private_key() method.",
            ),
        };

        let rpc_url = match self.rpc_url {
            Some(rpc_url) => rpc_url,
            None => std::env::var("NETWORK_RPC_URL").expect(
                "NETWORK_RPC_URL environment variable is not set. \
                Please set it to your rpc url or use the .rpc_url() method.",
            ),
        };

        NetworkProver::new(&private_key, &rpc_url)
    }
}

impl Default for NetworkProverBuilder {
    fn default() -> Self {
        Self { private_key: None, rpc_url: None }
    }
}
