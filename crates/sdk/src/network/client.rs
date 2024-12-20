//! # Network Client
//!
//! This module provides a client for directly interacting with the network prover service.

use std::result::Result::Ok as StdOk;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use anyhow::{Context, Ok, Result};
use reqwest_middleware::ClientWithMiddleware as HttpClientWithMiddleware;
use serde::{de::DeserializeOwned, Serialize};
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{HashableKey, SP1VerifyingKey};
use tonic::{
    transport::{channel::ClientTlsConfig, Channel},
    Code,
};

use super::utils::Signable;
use crate::network::proto::artifact::{
    artifact_store_client::ArtifactStoreClient, ArtifactType, CreateArtifactRequest,
};
use crate::network::proto::network::{
    prover_network_client::ProverNetworkClient, CreateProgramRequest, CreateProgramRequestBody,
    CreateProgramResponse, FulfillmentStatus, FulfillmentStrategy, GetFilteredProofRequestsRequest,
    GetFilteredProofRequestsResponse, GetNonceRequest, GetProgramRequest, GetProgramResponse,
    GetProofRequestStatusRequest, GetProofRequestStatusResponse, MessageFormat, ProofMode,
    RequestProofRequest, RequestProofRequestBody, RequestProofResponse,
};

/// A client for interacting with the network.
pub struct NetworkClient {
    pub(crate) signer: PrivateKeySigner,
    pub(crate) http: HttpClientWithMiddleware,
    pub(crate) rpc_url: String,
}

impl NetworkClient {
    /// Creates a new [`NetworkClient`] with the given private key and rpc url.
    pub fn new(private_key: impl Into<String>, rpc_url: impl Into<String>) -> Self {
        let signer = PrivateKeySigner::from_str(&private_key.into()).unwrap();
        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(0)
            .pool_idle_timeout(Duration::from_secs(240))
            .build()
            .unwrap();
        Self { signer, http: client.into(), rpc_url: rpc_url.into() }
    }

    /// Get the latest nonce for this account's address.
    pub async fn get_nonce(&self) -> Result<u64> {
        let mut rpc = self.prover_network_client().await?;
        let res =
            rpc.get_nonce(GetNonceRequest { address: self.signer.address().to_vec() }).await?;
        Ok(res.into_inner().nonce)
    }

    /// Get the verifying key hash from a verifying key.
    ///
    /// # Details
    /// The verifying key hash is used to identify a program.
    pub fn get_vk_hash(vk: &SP1VerifyingKey) -> Result<Vec<u8>> {
        let vk_hash_str = vk.bytes32();
        let vk_hash = hex::decode(vk_hash_str.strip_prefix("0x").unwrap_or(&vk_hash_str))?;
        Ok(vk_hash)
    }

    /// Registers a program with the network if it is not already registered.
    pub async fn register_program(&self, vk: &SP1VerifyingKey, elf: &[u8]) -> Result<Vec<u8>> {
        let vk_hash = Self::get_vk_hash(vk)?;

        // Try to get the existing program.
        if (self.get_program(&vk_hash).await?).is_some() {
            // The program already exists.
            Ok(vk_hash)
        } else {
            // The program doesn't exist, create it.
            self.create_program(&vk_hash, vk, elf).await?;
            log::info!("Registered program 0x{}", hex::encode(vk_hash.clone()));
            Ok(vk_hash)
        }
    }

    /// Attempts to get the program on the network.
    ///
    /// # Details
    /// Returns `None` if the program does not exist.
    pub async fn get_program(&self, vk_hash: &[u8]) -> Result<Option<GetProgramResponse>> {
        let mut rpc = self.prover_network_client().await?;
        match rpc.get_program(GetProgramRequest { vk_hash: vk_hash.to_vec() }).await {
            StdOk(response) => Ok(Some(response.into_inner())),
            Err(status) if status.code() == Code::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Creates a new program on the network.
    pub async fn create_program(
        &self,
        vk_hash: &[u8],
        vk: &SP1VerifyingKey,
        elf: &[u8],
    ) -> Result<CreateProgramResponse> {
        // Create the program artifact.
        let mut store = self.artifact_store_client().await?;
        let program_uri =
            self.create_artifact_with_content(&mut store, ArtifactType::Program, &elf).await?;

        // Serialize the verifying key.
        let vk_encoded = bincode::serialize(&vk)?;

        // Send the request.
        let mut rpc = self.prover_network_client().await?;
        let nonce = self.get_nonce().await?;
        let request_body = CreateProgramRequestBody {
            nonce,
            vk_hash: vk_hash.to_vec(),
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

    /// Get all the proof requests that meet the filter criteria.
    #[allow(clippy::too_many_arguments)]
    pub async fn get_filtered_proof_requests(
        &self,
        version: Option<String>,
        fulfillment_status: Option<i32>,
        execution_status: Option<i32>,
        minimum_deadline: Option<u64>,
        vk_hash: Option<Vec<u8>>,
        requester: Option<Vec<u8>>,
        fulfiller: Option<Vec<u8>>,
        from: Option<u64>,
        to: Option<u64>,
        limit: Option<u32>,
        page: Option<u32>,
        mode: Option<i32>,
    ) -> Result<GetFilteredProofRequestsResponse> {
        let mut rpc = self.prover_network_client().await?;
        let res = rpc
            .get_filtered_proof_requests(GetFilteredProofRequestsRequest {
                version,
                fulfillment_status,
                execution_status,
                minimum_deadline,
                vk_hash,
                requester,
                fulfiller,
                from,
                to,
                limit,
                page,
                mode,
            })
            .await?
            .into_inner();
        Ok(res)
    }

    /// Get the status of a given proof.
    ///
    /// # Details
    /// If the status is Fulfilled, the proof is also returned.
    pub async fn get_proof_request_status<P: DeserializeOwned>(
        &self,
        request_id: &[u8],
    ) -> Result<(GetProofRequestStatusResponse, Option<P>)> {
        let mut rpc = self.prover_network_client().await?;
        let res = rpc
            .get_proof_request_status(GetProofRequestStatusRequest {
                request_id: request_id.to_vec(),
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
                let proof_bytes = self.download_artifact(proof_uri).await?;
                Some(bincode::deserialize(&proof_bytes).context("Failed to deserialize proof")?)
            }
            _ => None,
        };

        Ok((res, proof))
    }

    /// Creates a proof request with the given verifying key hash and stdin.
    ///
    /// # Details
    /// * `vk_hash`: The verifying key hash of the program to prove. Used to identify the program.
    /// * `stdin`: The standard input to provide to the program.
    /// * `mode`: The [`ProofMode`] to use.
    /// * `version`: The version of the SP1 circuits to use.
    /// * `strategy`: The [`FulfillmentStrategy`] to use.
    /// * `timeout_secs`: The timeout for the proof request in seconds.
    /// * `cycle_limit`: The cycle limit for the proof request.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_proof(
        &self,
        vk_hash: &[u8],
        stdin: &SP1Stdin,
        mode: ProofMode,
        version: &str,
        strategy: FulfillmentStrategy,
        timeout_secs: u64,
        cycle_limit: u64,
    ) -> Result<RequestProofResponse> {
        // Calculate the deadline.
        let start = SystemTime::now();
        let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Invalid start time");
        let deadline = since_the_epoch.as_secs() + timeout_secs;

        // Create the stdin artifact.
        let mut store = self.artifact_store_client().await?;
        let stdin_uri =
            self.create_artifact_with_content(&mut store, ArtifactType::Stdin, &stdin).await?;

        // Send the request.
        let mut rpc = self.prover_network_client().await?;
        let nonce = self.get_nonce().await?;
        let request_body = RequestProofRequestBody {
            nonce,
            version: format!("sp1-{version}"),
            vk_hash: vk_hash.to_vec(),
            mode: mode.into(),
            strategy: strategy.into(),
            stdin_uri,
            deadline,
            cycle_limit,
        };
        let request_response = rpc
            .request_proof(RequestProofRequest {
                format: MessageFormat::Binary.into(),
                signature: request_body.sign(&self.signer).into(),
                body: Some(request_body),
            })
            .await?
            .into_inner();

        Ok(request_response)
    }

    pub(crate) async fn prover_network_client(&self) -> Result<ProverNetworkClient<Channel>> {
        let rpc_url = self.rpc_url.clone();
        let mut endpoint = Channel::from_shared(rpc_url.clone())?;

        // Check if the URL scheme is HTTPS and configure TLS.
        if rpc_url.starts_with("https://") {
            let tls_config = ClientTlsConfig::new().with_enabled_roots();
            endpoint = endpoint.tls_config(tls_config)?;
        }

        let channel = endpoint.connect().await?;
        Ok(ProverNetworkClient::new(channel))
    }

    pub(crate) async fn artifact_store_client(&self) -> Result<ArtifactStoreClient<Channel>> {
        let rpc_url = self.rpc_url.clone();
        let mut endpoint = Channel::from_shared(rpc_url.clone())?;

        // Check if the URL scheme is HTTPS and configure TLS.
        if rpc_url.starts_with("https://") {
            let tls_config = ClientTlsConfig::new().with_enabled_roots();
            endpoint = endpoint.tls_config(tls_config)?;
        }

        let channel = endpoint.connect().await?;
        Ok(ArtifactStoreClient::new(channel.clone()))
    }

    pub(crate) async fn create_artifact_with_content<T: Serialize>(
        &self,
        store: &mut ArtifactStoreClient<Channel>,
        artifact_type: ArtifactType,
        item: &T,
    ) -> Result<String> {
        let signature = self.signer.sign_message_sync("create_artifact".as_bytes())?;
        let request = CreateArtifactRequest {
            artifact_type: artifact_type.into(),
            signature: signature.as_bytes().to_vec(),
        };
        let response = store.create_artifact(request).await?.into_inner();

        let presigned_url = response.artifact_presigned_url;
        let uri = response.artifact_uri;

        let response =
            self.http.put(&presigned_url).body(bincode::serialize::<T>(item)?).send().await?;

        if !response.status().is_success() {
            log::debug!("Artifact upload failed with status: {}", response.status());
        }
        assert!(response.status().is_success());

        Ok(uri)
    }

    pub(crate) async fn download_artifact(&self, uri: &str) -> Result<Vec<u8>> {
        let response = self.http.get(uri).send().await.context("Failed to download from URI")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Failed to download artifact: HTTP {}", response.status()));
        }

        Ok(response.bytes().await.context("Failed to read response body")?.to_vec())
    }
}
