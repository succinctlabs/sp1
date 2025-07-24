use crate::private::prover::PrivateProver;

#[derive(Default)]
pub struct PrivateProverBuilder {
    private_key: Option<String>,
    rpc_url: Option<String>,
}

impl PrivateProverBuilder {
    /// Sets the Secp256k1 private key (same format as the one used by Ethereum).
    ///
    /// # Details
    /// Sets the private key that will be used sign requests sent to the network. By default, the
    /// private key is read from the `NETWORK_PRIVATE_KEY` environment variable.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let prover = ProverClient::builder().private().private_key("...").build();
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
    /// use sp1_sdk::ProverClient;
    ///
    /// let prover = ProverClient::builder().private().rpc_url("...").build();
    /// ```
    #[must_use]
    pub fn rpc_url(mut self, rpc_url: &str) -> Self {
        self.rpc_url = Some(rpc_url.to_string());
        self
    }

    #[must_use]
    pub fn build(self) -> PrivateProver {
        let private_key = self
            .private_key
            .expect("The private key ise required. Please set it with the .private_key() method.");
        let rpc_url = self
            .rpc_url
            .expect("The RPC URL ise required. Please set it with the .rpc_url() method.");

        PrivateProver::new(private_key, rpc_url)
    }
}
