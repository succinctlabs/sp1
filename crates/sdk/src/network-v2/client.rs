use std::{env, time::Duration};

use crate::network_v2::proto::artifact::{
    artifact_store_client::ArtifactStoreClient, CreateArtifactRequest,
};
use crate::network_v2::proto::network::{
    prover_network_client::ProverNetworkClient, GetFilteredProofRequestsRequest,
    GetFilteredProofRequestsResponse, GetNonceRequest, GetProofRequestStatusRequest,
    GetProofRequestStatusResponse, ProofMode, ProofStatus, ProofStrategy, RequestProofRequest,
    RequestProofRequestBody, RequestProofResponse,
};
use crate::network_v2::Signable;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use anyhow::{Context, Ok, Result};
use reqwest::Client as HttpClient;
use reqwest_middleware::ClientWithMiddleware as HttpClientWithMiddleware;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::SP1VerifyingKey;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::try_join;
use tonic::transport::Channel;

/// The default RPC endpoint for the Succinct prover network.
pub const DEFAULT_PROVER_NETWORK_RPC: &str = "http://127.0.0.1:50051";

pub struct NetworkClient {
    pub signer: PrivateKeySigner,
    pub rpc_url: String,
    pub http: HttpClientWithMiddleware,
}

impl NetworkClient {
    /// Returns the currently configured RPC endpoint for the Succinct prover network.
    pub fn rpc_url() -> String {
        env::var("PROVER_NETWORK_RPC").unwrap_or_else(|_| DEFAULT_PROVER_NETWORK_RPC.to_string())
    }

    // async fn create_channel(rpc_url: &str) -> Result<Channel> {
    //     Channel::from_shared(rpc_url.to_string())?
    //         .connect_timeout(Duration::from_secs(30))
    //         .tcp_keepalive(Some(Duration::from_secs(60)))
    //         .timeout(Duration::from_secs(60))
    //         .connect()
    //         .await
    //         .map_err(Into::into)
    // }

    // fn create_clients(
    //     channel: Channel,
    // ) -> (ProverNetworkClient<Channel>, ArtifactStoreClient<Channel>) {
    //     let rpc = ProverNetworkClient::new(channel.clone());
    //     let store = ArtifactStoreClient::new(channel);
    //     (rpc, store)
    // }

    // pub async fn new(private_key: &str) -> Result<Self> {
    //     let signer = PrivateKeySigner::from_str(private_key).unwrap();

    //     let rpc_url = Self::rpc_url();
    //     let channel = Self::create_channel(&rpc_url).await?;
    //     let (mut rpc, store) = Self::create_clients(channel);

    //     let http_client = HttpClient::builder()
    //         .pool_max_idle_per_host(0)
    //         .pool_idle_timeout(Duration::from_secs(240))
    //         .build()
    //         .unwrap();

    //     Ok(Self { signer, rpc, store, http: http_client.into() })
    // }

    // async fn ensure_connected(&mut self) -> Result<()> {
    //     let check_connection = async {
    //         // Try a simple RPC call to check the connection
    //         self.rpc
    //             .clone()
    //             .get_nonce(GetNonceRequest { address: self.signer.address().to_vec() })
    //             .await?;
    //         Ok(())
    //     };

    //     if check_connection.await.is_err() {
    //         log::warn!("Connection seems to be lost, reconnecting...");
    //         let rpc_url = Self::rpc_url();
    //         let channel = Self::create_channel(&rpc_url).await?;
    //         (self.rpc, self.store) = Self::create_clients(channel);
    //     }
    //     Ok(())
    // }

    pub fn new(private_key: &str) -> Self {
        let signer = PrivateKeySigner::from_str(private_key).unwrap();
        let rpc_url = Self::rpc_url();
        let http_client = HttpClient::builder()
            .pool_max_idle_per_host(0)
            .pool_idle_timeout(Duration::from_secs(240))
            .build()
            .unwrap();

        Self { signer, rpc_url, http: http_client.into() }
    }

    async fn connect(
        &self,
    ) -> Result<(ProverNetworkClient<Channel>, ArtifactStoreClient<Channel>)> {
        let rpc_url = Self::rpc_url();
        let channel = Channel::from_shared(rpc_url.clone())?.connect().await?;
        Ok((ProverNetworkClient::new(channel.clone()), ArtifactStoreClient::new(channel)))
    }

    /// Gets the latest nonce for this account's address.
    pub async fn get_nonce(&self) -> Result<u64> {
        let (mut rpc, _) = self.connect().await?;

        let res =
            rpc.get_nonce(GetNonceRequest { address: self.signer.address().to_vec() }).await?;
        Ok(res.into_inner().nonce)
    }

    /// Get the status of a given proof. If the status is ProofFulfilled, the proof is also
    /// returned.
    pub async fn get_proof_request_status<P: DeserializeOwned>(
        &self,
        request_id: &[u8],
    ) -> Result<(GetProofRequestStatusResponse, Option<P>)> {
        let (mut rpc, _) = self.connect().await?;

        let res = rpc
            .get_proof_request_status(GetProofRequestStatusRequest {
                request_id: request_id.to_vec(),
            })
            .await?
            .into_inner();
        let status = ProofStatus::try_from(res.status)?;
        let proof = match status {
            ProofStatus::Fulfilled => {
                log::info!("Proof request fulfilled");
                let proof_bytes = self
                    .http
                    .get(res.proof_uri.as_ref().expect("no proof url"))
                    .send()
                    .await
                    .context("Failed to send HTTP request for proof")?
                    .bytes()
                    .await
                    .context("Failed to load proof bytes")?;

                Some(bincode::deserialize(&proof_bytes).context("Failed to deserialize proof")?)
            }
            _ => None,
        };

        Ok((res, proof))
    }

    /// Get all the proof requests for a given status. Also filter by circuit version if provided.
    pub async fn get_filtered_proof_requests(
        &self,
        status: ProofStatus,
        circuit_version: Option<&str>,
    ) -> Result<GetFilteredProofRequestsResponse> {
        let (mut rpc, _) = self.connect().await?;
        let res = rpc
            .get_filtered_proof_requests(GetFilteredProofRequestsRequest {
                status: status.into(),
                version: circuit_version.map(|v| v.to_string()).unwrap_or_default(),
            })
            .await?
            .into_inner();

        Ok(res)
    }

    /// Creates a proof request with the given ELF and stdin.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_proof(
        &self,
        elf: &[u8],
        stdin: &SP1Stdin,
        vk: &SP1VerifyingKey,
        mode: ProofMode,
        _version: &str,
        strategy: ProofStrategy,
        timeout_secs: u64,
        cycle_limit: u64,
    ) -> Result<RequestProofResponse> {
        let (mut rpc, _) = self.connect().await?;

        let start = SystemTime::now();
        let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Invalid start time");
        let deadline = since_the_epoch.as_secs() + timeout_secs;

        // Create the program and stdin artifacts.
        let program_promise = self.create_artifact_with_content(&elf);
        let stdin_promise = self.create_artifact_with_content(&stdin);
        let (program_uri, stdin_uri) = try_join!(program_promise, stdin_promise)?;

        // Serialize the vkey.
        let vkey = bincode::serialize(&vk)?;

        let nonce = rpc
            .get_nonce(GetNonceRequest { address: self.signer.address().to_vec() })
            .await?
            .into_inner()
            .nonce;
        let request_body = RequestProofRequestBody {
            nonce,
            // version: version.to_string(),
            version: "sp1-v3.0.0-rc1".to_string(),
            vkey,
            mode: mode.into(),
            strategy: strategy.into(),
            program_uri,
            stdin_uri,
            deadline,
            cycle_limit,
        };

        log::info!("Requesting proof");

        let request_response = rpc
            .request_proof(RequestProofRequest {
                signature: request_body.sign(&self.signer).into(),
                body: Some(request_body),
            })
            .await?
            .into_inner();

        Ok(request_response)
    }

    /// Upload a file to the specified url.
    async fn upload_file(&self, url: &str, data: Vec<u8>) -> Result<()> {
        self.http.put(url).body(data).send().await?;
        Ok(())
    }

    /// Uses the artifact store to to create an artifact, upload the content, and return the URI.
    async fn create_artifact_with_content<T: Serialize>(&self, item: &T) -> Result<String> {
        let (_, store) = self.connect().await?;

        let signature = self.signer.sign_message_sync("create_artifact".as_bytes())?;
        let request = CreateArtifactRequest { signature: signature.as_bytes().to_vec() };
        let response = store.clone().create_artifact(request).await?.into_inner();

        let presigned_url = response.artifact_presigned_url;
        let uri = response.artifact_uri;

        let client = reqwest::Client::new();
        let response =
            client.put(&presigned_url).body(bincode::serialize::<T>(item)?).send().await?;

        assert!(response.status().is_success());

        Ok(uri)
    }
}
