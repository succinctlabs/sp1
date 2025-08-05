//! # Network Prover Builder
//!
//! This module provides a builder for the [`NetworkProver`].

use alloy_primitives::Address;

use crate::{
    network::{signer::NetworkSigner, DEFAULT_NETWORK_RPC_URL},
    NetworkProver,
};

#[cfg(feature = "tee-2fa")]
use crate::network::retry::{self, DEFAULT_RETRY_TIMEOUT};

/// A builder for the [`NetworkProver`].
///
/// The builder is used to configure the [`NetworkProver`] before it is built.
#[derive(Default)]
pub struct NetworkProverBuilder {
    pub(crate) private_key: Option<String>,
    pub(crate) rpc_url: Option<String>,
    pub(crate) tee_signers: Option<Vec<Address>>,
    pub(crate) signer: Option<NetworkSigner>,
}

impl NetworkProverBuilder {
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
    /// use sp1_sdk::ProverClient;
    ///
    /// let prover = ProverClient::builder().network().rpc_url("...").build();
    /// ```
    #[must_use]
    pub fn rpc_url(mut self, rpc_url: &str) -> Self {
        self.rpc_url = Some(rpc_url.to_string());
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
    ///
    /// # Examples
    ///
    /// Using a local private key:
    /// ```rust,no_run
    /// use sp1_sdk::{NetworkSigner, ProverClient};
    ///
    /// let private_key = "...";
    /// let signer = NetworkSigner::local(private_key).unwrap();
    /// let prover = ProverClient::builder().network().signer(signer).build();
    /// ```
    ///
    /// Using AWS KMS:
    /// ```rust,no_run
    /// use sp1_sdk::{NetworkSigner, ProverClient};
    ///
    /// # async fn example() {
    /// let kms_key_arn = "arn:aws:kms:us-east-1:123456789:key/key-id";
    /// let signer = NetworkSigner::aws_kms(kms_key_arn).await.unwrap();
    /// let prover = ProverClient::builder().network().signer(signer).build();
    /// # }
    /// ```
    #[must_use]
    pub fn signer(mut self, signer: NetworkSigner) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Builds a [`NetworkProver`].
    ///
    /// # Details
    /// This method will build a [`NetworkProver`] with the given parameters. If `signer` is
    /// provided, it will be used directly. Otherwise, if `private_key` is provided, a local
    /// signer will be created from it. If neither is provided, the method will look for the
    /// `NETWORK_PRIVATE_KEY` environment variable.
    ///
    /// # Examples
    ///
    /// Using a private key:
    /// ```rust,no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let prover = ProverClient::builder().network().private_key("...").rpc_url("...").build();
    /// ```
    ///
    /// Using a local signer:
    /// ```rust,no_run
    /// use sp1_sdk::{NetworkSigner, ProverClient};
    ///
    /// let private_key = "...";
    /// let signer = NetworkSigner::local(private_key).unwrap();
    /// let prover = ProverClient::builder().network().signer(signer).build();
    /// ```
    ///
    /// Using AWS KMS:
    /// ```rust,no_run
    /// use sp1_sdk::{NetworkSigner, ProverClient};
    ///
    /// # async fn example() {
    /// let kms_key_arn = "arn:aws:kms:us-east-1:123456789:key/key-id";
    /// let signer = NetworkSigner::aws_kms(kms_key_arn).await.unwrap();
    /// let prover = ProverClient::builder().network().signer(signer).build();
    /// # }
    /// ```
    #[must_use]
    pub fn build(self) -> NetworkProver {
        let signer = if let Some(provided_signer) = self.signer {
            provided_signer
        } else {
            let private_key = self
                .private_key
                .or_else(|| std::env::var("NETWORK_PRIVATE_KEY").ok().filter(|k| !k.is_empty()))
                .expect(
                    "NETWORK_PRIVATE_KEY environment variable is not set. \
                    Please set it to your private key or use the .private_key() method.",
                );
            NetworkSigner::local(&private_key).expect("Failed to create local signer")
        };

        let rpc_url = match self.rpc_url {
            Some(rpc_url) => rpc_url,
            None => std::env::var("NETWORK_RPC_URL").unwrap_or(DEFAULT_NETWORK_RPC_URL.to_string()),
        };

        let tee_signers = self.tee_signers.unwrap_or_else(|| {
            cfg_if::cfg_if! {
                if #[cfg(feature = "tee-2fa")] {
                    crate::utils::block_on(
                        async {
                            retry::retry_operation(
                                || async {
                                    crate::network::tee::get_tee_signers().await.map_err(Into::into)
                                },
                                Some(DEFAULT_RETRY_TIMEOUT),
                                "get tee signers"
                            ).await.expect("Failed to get TEE signers")
                        }
                    )
                } else {
                    vec![]
                }
            }
        });

        NetworkProver::new(signer, &rpc_url).with_tee_signers(tee_signers)
    }
}
