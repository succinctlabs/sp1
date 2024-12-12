use std::result::Result::Ok as StdOk;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use anyhow::{Context, Ok, Result};
use reqwest_middleware::ClientWithMiddleware as HttpClientWithMiddleware;
use serde::{de::DeserializeOwned, Serialize};
use tonic::{
    transport::{channel::ClientTlsConfig, Channel},
    Code,
};

use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{HashableKey, SP1VerifyingKey};

use crate::network_v2::proto::artifact::{
    artifact_store_client::ArtifactStoreClient, CreateArtifactRequest,
};
use crate::network_v2::proto::network::{
    prover_network_client::ProverNetworkClient, CreateProgramRequest, CreateProgramRequestBody,
    CreateProgramResponse, FulfillmentStatus, FulfillmentStrategy, GetNonceRequest,
    GetProgramRequest, GetProgramResponse, GetProofRequestStatusRequest,
    GetProofRequestStatusResponse, MessageFormat, ProofMode, RequestProofRequest,
    RequestProofRequestBody,
};
use crate::network_v2::types::{HashType, RequestId, TransactionHash, VerifyingKeyHash};
use crate::network_v2::{Error, Signable};

/// The default RPC endpoint for the Succinct prover network.
pub const DEFAULT_PROVER_NETWORK_RPC: &str = "https://rpc.production.succinct.tools/";

pub struct NetworkClient {
    signer: PrivateKeySigner,
    http: HttpClientWithMiddleware,
    rpc_url: String,
}

impl NetworkClient {
    /// Create a new network client with the given private key.
    pub fn new(private_key: &str) -> Self {
        let signer = PrivateKeySigner::from_str(private_key).unwrap();

        let http_client = reqwest::Client::builder()
            .pool_max_idle_per_host(0)
            .pool_idle_timeout(Duration::from_secs(240))
            .build()
            .unwrap();

        Self { signer, http: http_client.into(), rpc_url: DEFAULT_PROVER_NETWORK_RPC.to_string() }
    }

    /// Update the RPC URL for the client.
    pub fn rpc_url(mut self, rpc_url: impl Into<String>) -> Self {
        self.rpc_url = rpc_url.into();
        self
    }

    /// Returns the currently configured RPC endpoint for the Succinct prover network.
    pub fn get_rpc_url(&self) -> String {
        self.rpc_url.clone()
    }

    /// Get a connected RPC client.
    async fn get_rpc(&self) -> Result<ProverNetworkClient<Channel>> {
        let rpc_url = self.get_rpc_url();
        let mut endpoint = Channel::from_shared(rpc_url.clone())?;

        // Check if the URL scheme is HTTPS and configure TLS.
        if rpc_url.starts_with("https://") {
            let tls_config = ClientTlsConfig::new().with_enabled_roots();
            endpoint = endpoint.tls_config(tls_config)?;
        }

        let channel = endpoint.connect().await?;
        Ok(ProverNetworkClient::new(channel))
    }

    /// Get a connected artifact store client.
    async fn get_store(&self) -> Result<ArtifactStoreClient<Channel>> {
        let rpc_url = self.get_rpc_url();
        let mut endpoint = Channel::from_shared(rpc_url.clone())?;

        // Check if the URL scheme is HTTPS and configure TLS.
        if rpc_url.starts_with("https://") {
            let tls_config = ClientTlsConfig::new().with_enabled_roots();
            endpoint = endpoint.tls_config(tls_config)?;
        }

        let channel = endpoint.connect().await?;
        Ok(ArtifactStoreClient::new(channel.clone()))
    }

    /// Get the latest nonce for this account's address.
    pub async fn get_nonce(&self) -> Result<u64> {
        let mut rpc = self.get_rpc().await?;
        let res =
            rpc.get_nonce(GetNonceRequest { address: self.signer.address().to_vec() }).await?;
        Ok(res.into_inner().nonce)
    }

    /// Get the verifying key hash from a verifying key.
    pub fn get_vk_hash(vk: &SP1VerifyingKey) -> Result<VerifyingKeyHash> {
        let vk_hash_str = vk.bytes32();
        let vk_hash = hex::decode(vk_hash_str.strip_prefix("0x").unwrap_or(&vk_hash_str))?;
        Ok(VerifyingKeyHash::new(vk_hash))
    }

    /// Registers a program if it is not already registered.
    pub async fn register_program(
        &self,
        vk: &SP1VerifyingKey,
        elf: &[u8],
    ) -> Result<VerifyingKeyHash> {
        let vk_hash = Self::get_vk_hash(vk)?;

        // Try to get the existing program.
        match self.get_program(&vk_hash).await? {
            Some(_) => {
                // The program already exists.
                Ok(vk_hash)
            }
            None => {
                // The program doesn't exist, create it.
                self.create_program(&vk_hash, vk, elf).await?;
                log::info!("Registered program {}", vk_hash);
                Ok(vk_hash)
            }
        }
    }

    /// Attempts to get program info, returns None if program doesn't exist.
    async fn get_program(&self, vk_hash: &VerifyingKeyHash) -> Result<Option<GetProgramResponse>> {
        let mut rpc = self.get_rpc().await?;
        match rpc.get_program(GetProgramRequest { vk_hash: vk_hash.as_bytes().to_vec() }).await {
            StdOk(response) => Ok(Some(response.into_inner())),
            Err(status) if status.code() == Code::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Creates a new program.
    async fn create_program(
        &self,
        vk_hash: &VerifyingKeyHash,
        vk: &SP1VerifyingKey,
        elf: &[u8],
    ) -> Result<CreateProgramResponse> {
        // Create the program artifact.
        let mut store = self.get_store().await?;
        let program_uri = self.create_artifact_with_content(&mut store, &elf).await?;

        // Serialize the verifying key.
        let vk_encoded = bincode::serialize(&vk)?;

        // Send the request.
        let mut rpc = self.get_rpc().await?;
        let nonce = self.get_nonce().await?;
        let request_body = CreateProgramRequestBody {
            nonce,
            vk_hash: vk_hash.as_bytes().to_vec(),
            vk: vk_encoded,
            program_uri,
        };

        Ok(rpc
            .create_program(CreateProgramRequest {
                format: MessageFormat::Binary.into(),
                signature: request_body.sign(&self.signer).into(),
                body: Some(request_body),
            })
            .await?
            .into_inner())
    }

    /// Get the status of a given proof. If the status is Fulfilled, the proof is also returned.
    pub async fn get_proof_request_status<P: DeserializeOwned>(
        &self,
        request_id: &RequestId,
    ) -> Result<(GetProofRequestStatusResponse, Option<P>)> {
        let mut rpc = self.get_rpc().await?;
        let res = rpc
            .get_proof_request_status(GetProofRequestStatusRequest {
                request_id: request_id.as_bytes().to_vec(),
            })
            .await?
            .into_inner();

        let status = FulfillmentStatus::try_from(res.fulfillment_status)?;
        let proof = match status {
            FulfillmentStatus::Fulfilled => {
                let proof_uri = res
                    .proof_uri
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("No proof URI provided"))?;
                let proof_bytes = self
                    .download_artifact(proof_uri)
                    .await
                    .map_err(|e| Error::ArtifactDownload { message: e.to_string() })?;
                Some(bincode::deserialize(&proof_bytes).context("Failed to deserialize proof")?)
            }
            _ => None,
        };

        Ok((res, proof))
    }

    /// Creates a proof request with the given verifying key hash and stdin.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_proof(
        &self,
        vk_hash: &VerifyingKeyHash,
        stdin: &SP1Stdin,
        version: &str,
        mode: ProofMode,
        strategy: FulfillmentStrategy,
        timeout_secs: u64,
        cycle_limit: u64,
    ) -> Result<(TransactionHash, RequestId)> {
        // Calculate the deadline.
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::Other(anyhow::anyhow!("Invalid system time: {}", e)))?;
        let deadline = since_the_epoch.as_secs() + timeout_secs;

        // Create the stdin artifact.
        let mut store = self.get_store().await?;
        let stdin_uri = self.create_artifact_with_content(&mut store, &stdin).await?;

        // Send the request.
        let mut rpc = self.get_rpc().await?;
        let nonce = self.get_nonce().await?;
        let request_body = RequestProofRequestBody {
            nonce,
            version: format!("sp1-{}", version),
            vk_hash: vk_hash.as_bytes().to_vec(),
            mode: mode.into(),
            strategy: strategy.into(),
            stdin_uri,
            deadline,
            cycle_limit,
        };
        let response = rpc
            .request_proof(RequestProofRequest {
                format: MessageFormat::Binary.into(),
                signature: request_body.sign(&self.signer).into(),
                body: Some(request_body),
            })
            .await?
            .into_inner();

        let tx_hash = TransactionHash::new(response.tx_hash);
        let request_id = RequestId::new(
            response
                .body
                .ok_or_else(|| Error::Other(anyhow::anyhow!("Missing response body")))?
                .request_id,
        );

        Ok((tx_hash, request_id))
    }

    /// Uses the artifact store to to create an artifact, upload the content, and return the URI.
    async fn create_artifact_with_content<T: Serialize>(
        &self,
        store: &mut ArtifactStoreClient<Channel>,
        item: &T,
    ) -> Result<String> {
        let signature = self.signer.sign_message_sync("create_artifact".as_bytes())?;
        let request = CreateArtifactRequest { signature: signature.as_bytes().to_vec() };
        let response = store.create_artifact(request).await?.into_inner();

        let presigned_url = response.artifact_presigned_url;
        let uri = response.artifact_uri;

        let response =
            self.http.put(&presigned_url).body(bincode::serialize::<T>(item)?).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response
                .text()
                .await
                .unwrap_or_else(|e| format!("Failed to get error response text: {}", e));
            return Err(anyhow::anyhow!("HTTP {}: {}", status, text));
        }

        Ok(uri)
    }

    /// Download an artifact from a URI.
    async fn download_artifact(&self, uri: &str) -> Result<Vec<u8>> {
        let response = self.http.get(uri).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response
                .text()
                .await
                .unwrap_or_else(|e| format!("Failed to get error response text: {}", e));
            return Err(anyhow::anyhow!("HTTP {}: {}", status, text));
        }

        Ok(response.bytes().await?.to_vec())
    }
}
