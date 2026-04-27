//! # Network Client
//!
//! This module provides a client for directly interacting with the network prover service.

use std::{
    result::Result::Ok as StdOk,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy_primitives::{Address, B256, U256};
use anyhow::{Context, Ok, Result};
use async_trait::async_trait;
use reqwest_middleware::ClientWithMiddleware as HttpClientWithMiddleware;
use serde::{de::DeserializeOwned, Serialize};
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{HashableKey, SP1VerifyingKey};
use tonic::{transport::Channel, Code};

use super::{
    grpc,
    retry::{self, RetryableRpc, DEFAULT_RETRY_TIMEOUT},
    signer::NetworkSigner,
    utils::{sign_message, Signable},
    NetworkMode, MAINNET_EXPLORER_URL, RESERVED_EXPLORER_URL,
};
use crate::network::proto::{
    artifact::{artifact_store_client::ArtifactStoreClient, ArtifactType, CreateArtifactRequest},
    // Import the clients for both auction and base.
    auction_network::prover_network_client::ProverNetworkClient as AuctionProverNetworkClient,
    // Import auction and base specific types for requests.
    auction_types::{
        CancelRequestRequest as AuctionCancelRequestRequest,
        CancelRequestRequestBody as AuctionCancelRequestRequestBody,
        GetBalanceRequest as AuctionGetBalanceRequest,
        GetFilteredProofRequestsRequest as AuctionGetFilteredProofRequestsRequest,
        GetNonceRequest as AuctionGetNonceRequest, GetProgramRequest as AuctionGetProgramRequest,
        GetProofRequestParamsRequest as AuctionGetProofRequestParamsRequest,
        GetProofRequestStatusRequest as AuctionGetProofRequestStatusRequest,
        GetProversByUptimeRequest as AuctionGetProversByUptimeRequest,
        MessageFormat as AuctionMessageFormat, RequestProofRequest as AuctionRequestProofRequest,
        RequestProofRequestBody as AuctionRequestProofRequestBody,
        TransactionVariant as AuctionTransactionVariant,
    },
    base_network::prover_network_client::ProverNetworkClient as BaseProverNetworkClient,
    base_types::{
        GetBalanceRequest as BaseGetBalanceRequest,
        GetFilteredProofRequestsRequest as BaseGetFilteredProofRequestsRequest,
        GetNonceRequest as BaseGetNonceRequest, GetProgramRequest as BaseGetProgramRequest,
        GetProofRequestStatusRequest as BaseGetProofRequestStatusRequest,
        MessageFormat as BaseMessageFormat, RequestProofRequest as BaseRequestProofRequest,
        RequestProofRequestBody as BaseRequestProofRequestBody,
    },
    // Import standard types (auction by default for backwards compatibility).
    types::{
        CreateProgramRequest, CreateProgramRequestBody, CreateProgramResponse, FulfillmentStatus,
        FulfillmentStrategy, GetProofRequestDetailsRequest, GetProofRequestDetailsResponse,
        MessageFormat, ProofMode,
    },
    CancelRequestResponse,
    GetBalanceResponse,
    GetFilteredProofRequestsResponse,
    // Import unified switchable response types.
    GetNonceResponse,
    GetProgramResponse,
    GetProofRequestParamsResponse,
    GetProofRequestStatusResponse,
    RequestProofResponse,
};

/// A client for interacting with the network.
#[derive(Clone)]
pub struct NetworkClient {
    pub(crate) signer: NetworkSigner,
    pub(crate) http: HttpClientWithMiddleware,
    pub(crate) rpc_url: String,
    pub(crate) network_mode: NetworkMode,
}

#[async_trait]
impl RetryableRpc for NetworkClient {
    /// Execute an operation with retries using default timeout.
    async fn with_retry<'a, T, F, Fut>(&'a self, operation: F, operation_name: &str) -> Result<T>
    where
        F: Fn() -> Fut + Send + Sync + 'a,
        Fut: std::future::Future<Output = Result<T>> + Send,
        T: Send,
    {
        self.with_retry_timeout(operation, DEFAULT_RETRY_TIMEOUT, operation_name).await
    }

    /// Execute an operation with retries using the specified timeout.
    async fn with_retry_timeout<'a, T, F, Fut>(
        &'a self,
        operation: F,
        timeout: Duration,
        operation_name: &str,
    ) -> Result<T>
    where
        F: Fn() -> Fut + Send + Sync + 'a,
        Fut: std::future::Future<Output = Result<T>> + Send,
        T: Send,
    {
        retry::retry_operation(operation, Some(timeout), operation_name).await
    }
}

impl NetworkClient {
    /// Creates a new [`NetworkClient`] with the given signer, rpc url, and network mode.
    pub fn new(
        signer: NetworkSigner,
        rpc_url: impl Into<String>,
        network_mode: NetworkMode,
    ) -> Self {
        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(0)
            .pool_idle_timeout(Duration::from_secs(240))
            .build()
            .unwrap();
        Self { signer, http: client.into(), rpc_url: rpc_url.into(), network_mode }
    }

    /// Get the explorer URL for the current network mode.
    #[must_use]
    pub fn get_explorer_url(&self) -> &'static str {
        match self.network_mode {
            NetworkMode::Mainnet => MAINNET_EXPLORER_URL,
            NetworkMode::Reserved => RESERVED_EXPLORER_URL,
        }
    }

    /// Get the latest nonce for this account's address.
    pub async fn get_nonce(&self) -> Result<u64> {
        let response = self.get_nonce_response().await?;
        Ok(response.nonce())
    }

    /// Get the full nonce response (internal helper).
    async fn get_nonce_response(&self) -> Result<GetNonceResponse> {
        match self.network_mode {
            NetworkMode::Mainnet => {
                self.with_retry(
                    || async {
                        let mut rpc = self.auction_prover_network_client().await?;
                        let res = rpc
                            .get_nonce(AuctionGetNonceRequest {
                                address: self.signer.address().to_vec(),
                            })
                            .await?;
                        Ok(GetNonceResponse::from(res.into_inner()))
                    },
                    "getting nonce",
                )
                .await
            }
            NetworkMode::Reserved => {
                self.with_retry(
                    || async {
                        let mut rpc = self.base_prover_network_client().await?;
                        let res = rpc
                            .get_nonce(BaseGetNonceRequest {
                                address: self.signer.address().to_vec(),
                            })
                            .await?;
                        Ok(GetNonceResponse::from(res.into_inner()))
                    },
                    "getting nonce",
                )
                .await
            }
        }
    }

    /// Get the credit balance of your account.
    ///
    /// # Details
    /// Uses the key that the client was initialized with.
    pub async fn get_balance(&self) -> Result<U256> {
        let response = self.get_balance_response().await?;
        Ok(U256::from_str(response.balance()).unwrap())
    }

    /// Get the full balance response (internal helper).
    async fn get_balance_response(&self) -> Result<GetBalanceResponse> {
        match self.network_mode {
            NetworkMode::Mainnet => {
                self.with_retry(
                    || async {
                        let mut rpc = self.auction_prover_network_client().await?;
                        let res = rpc
                            .get_balance(AuctionGetBalanceRequest {
                                address: self.signer.address().to_vec(),
                            })
                            .await?;
                        Ok(GetBalanceResponse::from(res.into_inner()))
                    },
                    "getting balance",
                )
                .await
            }
            NetworkMode::Reserved => {
                self.with_retry(
                    || async {
                        let mut rpc = self.base_prover_network_client().await?;
                        let res = rpc
                            .get_balance(BaseGetBalanceRequest {
                                address: self.signer.address().to_vec(),
                            })
                            .await?;
                        Ok(GetBalanceResponse::from(res.into_inner()))
                    },
                    "getting balance",
                )
                .await
            }
        }
    }

    /// Get the verifying key hash from a verifying key.
    ///
    /// # Details
    /// The verifying key hash is used to identify a program.
    pub fn get_vk_hash(vk: &SP1VerifyingKey) -> Result<B256> {
        let vk_hash = vk.hash_bytes();
        Ok(B256::from_slice(&vk_hash))
    }

    /// Registers a program with the network if it is not already registered.
    pub async fn register_program(&self, vk: &SP1VerifyingKey, elf: &[u8]) -> Result<B256> {
        let vk_hash = Self::get_vk_hash(vk)?;

        // Try to get the existing program.
        if (self.get_program(vk_hash).await?).is_some() {
            // The program already exists.
            Ok(vk_hash)
        } else {
            // The program doesn't exist, create it.
            self.create_program(vk_hash, vk, elf).await?;
            tracing::info!("Registered program {:?}", vk_hash);
            Ok(vk_hash)
        }
    }

    /// Attempts to get the program on the network.
    ///
    /// # Details
    /// Returns `None` if the program does not exist.
    pub async fn get_program(&self, vk_hash: B256) -> Result<Option<GetProgramResponse>> {
        match self.network_mode {
            NetworkMode::Mainnet => {
                self.with_retry(
                    || async {
                        let mut rpc = self.auction_prover_network_client().await?;
                        match rpc
                            .get_program(AuctionGetProgramRequest { vk_hash: vk_hash.to_vec() })
                            .await
                        {
                            StdOk(response) => {
                                Ok(Some(GetProgramResponse::from(response.into_inner())))
                            }
                            Err(status) if status.code() == Code::NotFound => Ok(None),
                            Err(e) => Err(e.into()),
                        }
                    },
                    "getting program",
                )
                .await
            }
            NetworkMode::Reserved => {
                self.with_retry(
                    || async {
                        let mut rpc = self.base_prover_network_client().await?;
                        match rpc
                            .get_program(BaseGetProgramRequest { vk_hash: vk_hash.to_vec() })
                            .await
                        {
                            StdOk(response) => {
                                Ok(Some(GetProgramResponse::from(response.into_inner())))
                            }
                            Err(status) if status.code() == Code::NotFound => Ok(None),
                            Err(e) => Err(e.into()),
                        }
                    },
                    "getting program",
                )
                .await
            }
        }
    }

    /// Creates a new program on the network.
    pub async fn create_program(
        &self,
        vk_hash: B256,
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
        self.with_retry(
            || async {
                let mut rpc = self.prover_network_client().await?;
                let nonce = self.get_nonce().await?;
                let request_body = CreateProgramRequestBody {
                    nonce,
                    vk_hash: vk_hash.to_vec(),
                    vk: vk_encoded.clone(),
                    program_uri: program_uri.clone(),
                };

                Ok(rpc
                    .create_program(CreateProgramRequest {
                        format: MessageFormat::Binary.into(),
                        signature: request_body.sign(&self.signer).await?,
                        body: Some(request_body),
                    })
                    .await?
                    .into_inner())
            },
            "creating program",
        )
        .await
    }

    /// Gets the proof request parameters from the network.
    /// This is only available in Mainnet (auction) mode.
    pub async fn get_proof_request_params(
        &self,
        mode: ProofMode,
    ) -> Result<GetProofRequestParamsResponse> {
        match self.network_mode {
            NetworkMode::Mainnet => {
                self.with_retry(
                    || async {
                        let mut rpc = self.auction_prover_network_client().await?;
                        let response = rpc
                            .get_proof_request_params(AuctionGetProofRequestParamsRequest {
                                mode: mode.into(),
                            })
                            .await?
                            .into_inner();
                        Ok(GetProofRequestParamsResponse::from(response))
                    },
                    "getting proof request parameters",
                )
                .await
            }
            NetworkMode::Reserved => Ok(GetProofRequestParamsResponse::Unsupported),
        }
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
        not_bid_by: Option<Vec<u8>>,
        execute_fail_cause: Option<i32>,
        settlement_status: Option<i32>,
        error: Option<i32>,
    ) -> Result<GetFilteredProofRequestsResponse> {
        match self.network_mode {
            NetworkMode::Mainnet => {
                self.with_retry(
                    || {
                        let version = version.clone();
                        let vk_hash = vk_hash.clone();
                        let requester = requester.clone();
                        let fulfiller = fulfiller.clone();
                        let not_bid_by = not_bid_by.clone();

                        async move {
                            let mut rpc = self.auction_prover_network_client().await?;
                            let response = rpc
                                .get_filtered_proof_requests(
                                    AuctionGetFilteredProofRequestsRequest {
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
                                        not_bid_by,
                                        execute_fail_cause,
                                        settlement_status,
                                        error,
                                    },
                                )
                                .await?
                                .into_inner();
                            Ok(GetFilteredProofRequestsResponse::from(response))
                        }
                    },
                    "getting filtered proof requests",
                )
                .await
            }
            NetworkMode::Reserved => {
                self.with_retry(
                    || {
                        let version = version.clone();
                        let vk_hash = vk_hash.clone();
                        let requester = requester.clone();
                        let fulfiller = fulfiller.clone();
                        let not_bid_by = not_bid_by.clone();

                        async move {
                            let mut rpc = self.base_prover_network_client().await?;
                            let response = rpc
                                .get_filtered_proof_requests(BaseGetFilteredProofRequestsRequest {
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
                                    not_bid_by,
                                    execute_fail_cause,
                                    settlement_status,
                                    error,
                                })
                                .await?
                                .into_inner();
                            Ok(GetFilteredProofRequestsResponse::from(response))
                        }
                    },
                    "getting filtered proof requests",
                )
                .await
            }
        }
    }

    /// Get the status of a given proof.
    ///
    /// # Details
    /// If the status is Fulfilled, the proof is also returned.
    pub async fn get_proof_request_status<P: DeserializeOwned>(
        &self,
        request_id: B256,
        timeout: Option<Duration>,
    ) -> Result<(GetProofRequestStatusResponse, Option<P>)> {
        // Get the status.
        let res = match self.network_mode {
            NetworkMode::Mainnet => {
                let auction_response = self
                    .with_retry_timeout(
                        || async {
                            let mut rpc = self.auction_prover_network_client().await?;
                            Ok(rpc
                                .get_proof_request_status(AuctionGetProofRequestStatusRequest {
                                    request_id: request_id.to_vec(),
                                })
                                .await?
                                .into_inner())
                        },
                        timeout.unwrap_or(DEFAULT_RETRY_TIMEOUT),
                        "getting proof request status",
                    )
                    .await?;
                GetProofRequestStatusResponse::from(auction_response)
            }
            NetworkMode::Reserved => {
                let base_response = self
                    .with_retry_timeout(
                        || async {
                            let mut rpc = self.base_prover_network_client().await?;
                            Ok(rpc
                                .get_proof_request_status(BaseGetProofRequestStatusRequest {
                                    request_id: request_id.to_vec(),
                                })
                                .await?
                                .into_inner())
                        },
                        timeout.unwrap_or(DEFAULT_RETRY_TIMEOUT),
                        "getting proof request status",
                    )
                    .await?;
                GetProofRequestStatusResponse::from(base_response)
            }
        };

        let status = FulfillmentStatus::try_from(res.fulfillment_status())?;
        let proof = match status {
            FulfillmentStatus::Fulfilled => {
                let proof_uri =
                    res.proof_uri().ok_or_else(|| anyhow::anyhow!("No proof URI provided"))?;
                let proof_bytes = self.download_artifact(proof_uri).await?;
                Some(bincode::deserialize(&proof_bytes).context("Failed to deserialize proof")?)
            }
            _ => None,
        };

        Ok((res, proof))
    }

    /// Get the details of a given proof request.
    pub async fn get_proof_request_details(
        &self,
        request_id: B256,
        timeout: Option<Duration>,
    ) -> Result<GetProofRequestDetailsResponse> {
        let res = self
            .with_retry_timeout(
                || async {
                    let mut rpc = self.prover_network_client().await?;
                    Ok(rpc
                        .get_proof_request_details(GetProofRequestDetailsRequest {
                            request_id: request_id.to_vec(),
                        })
                        .await?
                        .into_inner())
                },
                timeout.unwrap_or(DEFAULT_RETRY_TIMEOUT),
                "getting proof request details",
            )
            .await?;

        Ok(res)
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
    /// * `gas_limit`: The gas limit for the proof request.
    /// * `min_auction_period`: The minimum auction period for the proof request in seconds.
    /// * `whitelist`: The auction whitelist for the proof request.
    /// * `auctioneer`: The auctioneer for the proof request.
    /// * `executor`: The executor for the proof request.
    /// * `verifier`: The verifier for the proof request.
    /// * `treasury`: The treasury for the proof request.
    /// * `public_values_hash`: The hash of the public values to use for the proof.
    /// * `base_fee`: The base fee to use for the proof request.
    /// * `max_price_per_pgu`: The maximum price per PGU to use for the proof request.
    /// * `domain`: The domain bytes to use for the proof request.
    #[allow(clippy::too_many_arguments)]
    #[allow(unused_variables)]
    pub async fn request_proof(
        &self,
        vk_hash: B256,
        stdin: &SP1Stdin,
        mode: ProofMode,
        version: &str,
        strategy: FulfillmentStrategy,
        timeout_secs: u64,
        cycle_limit: u64,
        gas_limit: u64,
        min_auction_period: u64,
        whitelist: Option<Vec<Address>>,
        auctioneer: Address,
        executor: Address,
        verifier: Address,
        treasury: Address,
        public_values_hash: Option<Vec<u8>>,
        base_fee: u64,
        max_price_per_pgu: u64,
        domain: Vec<u8>,
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
        match self.network_mode {
            NetworkMode::Mainnet => {
                self.with_retry(
                    || async {
                        let mut rpc = self.auction_prover_network_client().await?;
                        let nonce = self.get_nonce().await?;

                        let whitelist = if let Some(whitelist) = &whitelist {
                            whitelist.iter().map(|addr| addr.to_vec()).collect()
                        } else {
                            let result = rpc
                                .get_provers_by_uptime(AuctionGetProversByUptimeRequest {
                                    high_availability_only: false,
                                })
                                .await?;
                            result.into_inner().provers
                        };

                        let request_body = AuctionRequestProofRequestBody {
                            nonce,
                            version: format!("sp1-{version}"),
                            vk_hash: vk_hash.to_vec(),
                            mode: mode.into(),
                            strategy: strategy.into(),
                            stdin_uri: stdin_uri.clone(),
                            deadline,
                            cycle_limit,
                            gas_limit,
                            min_auction_period,
                            whitelist,
                            domain: domain.clone(),
                            auctioneer: auctioneer.to_vec(),
                            executor: executor.to_vec(),
                            verifier: verifier.to_vec(),
                            treasury: treasury.to_vec(),
                            public_values_hash: public_values_hash.clone(),
                            base_fee: base_fee.to_string(),
                            max_price_per_pgu: max_price_per_pgu.to_string(),
                            variant: AuctionTransactionVariant::RequestVariant.into(),
                        };

                        let request_response = rpc
                            .request_proof(AuctionRequestProofRequest {
                                format: AuctionMessageFormat::Binary.into(),
                                signature: request_body.sign(&self.signer).await?,
                                body: Some(request_body),
                            })
                            .await?
                            .into_inner();

                        Ok(RequestProofResponse::from(request_response))
                    },
                    "requesting proof",
                )
                .await
            }
            NetworkMode::Reserved => {
                self.with_retry(
                    || async {
                        let mut rpc = self.base_prover_network_client().await?;
                        let nonce = self.get_nonce().await?;

                        let request_body = BaseRequestProofRequestBody {
                            nonce,
                            version: format!("sp1-{version}"),
                            vk_hash: vk_hash.to_vec(),
                            mode: mode.into(),
                            strategy: strategy.into(),
                            stdin_uri: stdin_uri.clone(),
                            deadline,
                            cycle_limit,
                            gas_limit,
                            min_auction_period,
                            whitelist: whitelist
                                .clone()
                                .map(|list| list.into_iter().map(|addr| addr.to_vec()).collect())
                                .unwrap_or_default(),
                        };

                        let request_response = rpc
                            .request_proof(BaseRequestProofRequest {
                                format: BaseMessageFormat::Binary.into(),
                                signature: request_body.sign(&self.signer).await?,
                                body: Some(request_body),
                            })
                            .await?
                            .into_inner();

                        Ok(RequestProofResponse::from(request_response))
                    },
                    "requesting proof",
                )
                .await
            }
        }
    }

    // NetworkMode-aware generic client for shared operations (create_program,
    // get_proof_request_details).
    pub(crate) async fn prover_network_client(
        &self,
    ) -> Result<AuctionProverNetworkClient<Channel>> {
        // For shared operations, we use the auction client type as it provides the default types.
        // The actual network routing is handled by the RPC URL which is correctly set based on
        // network_mode.
        self.auction_prover_network_client().await
    }

    // Helper methods for runtime proto type selection.
    pub(crate) async fn auction_prover_network_client(
        &self,
    ) -> Result<AuctionProverNetworkClient<Channel>> {
        self.with_retry(
            || async {
                let channel = grpc::configure_endpoint(&self.rpc_url)?.connect().await?;
                Ok(AuctionProverNetworkClient::new(channel))
            },
            "creating auction network client",
        )
        .await
    }

    pub(crate) async fn base_prover_network_client(
        &self,
    ) -> Result<BaseProverNetworkClient<Channel>> {
        self.with_retry(
            || async {
                let channel = grpc::configure_endpoint(&self.rpc_url)?.connect().await?;
                Ok(BaseProverNetworkClient::new(channel))
            },
            "creating base network client",
        )
        .await
    }

    pub(crate) async fn artifact_store_client(&self) -> Result<ArtifactStoreClient<Channel>> {
        self.with_retry(
            || async {
                let channel = grpc::configure_endpoint(&self.rpc_url)?.connect().await?;
                Ok(ArtifactStoreClient::new(channel))
            },
            "creating artifact client",
        )
        .await
    }

    pub(crate) async fn create_artifact_with_content<T: Serialize + Send + Sync>(
        &self,
        store: &mut ArtifactStoreClient<Channel>,
        artifact_type: ArtifactType,
        item: &T,
    ) -> Result<String> {
        let signature = sign_message("create_artifact".as_bytes(), &self.signer).await?;
        let request = CreateArtifactRequest { artifact_type: artifact_type.into(), signature };

        // Create the artifact.
        let response = store.create_artifact(request).await?.into_inner();

        let presigned_url = response.artifact_presigned_url;
        let uri = response.artifact_uri;

        // Serialize and compress the content once before retrying uploads.
        // Using compression level 3 for a good balance of speed and compression ratio.
        let serialized = bincode::serialize::<T>(item)?;
        let compressed = zstd::encode_all(&serialized[..], 3)
            .map_err(|e| anyhow::anyhow!("Failed to compress artifact: {e}"))?;

        // Upload the compressed content.
        self.with_retry(
            || async {
                let response =
                    self.http.put(&presigned_url).body(compressed.clone()).send().await?;

                if !response.status().is_success() {
                    return Err(anyhow::anyhow!(
                        "Failed to upload artifact: HTTP {}",
                        response.status()
                    ));
                }
                Ok(())
            },
            "uploading artifact content",
        )
        .await?;

        Ok(uri)
    }

    pub(crate) async fn download_artifact(&self, uri: &str) -> Result<Vec<u8>> {
        self.with_retry(
            || async {
                let response =
                    self.http.get(uri).send().await.context("Failed to download from URI")?;

                if !response.status().is_success() {
                    return Err(anyhow::anyhow!(
                        "Failed to download artifact: HTTP {}",
                        response.status()
                    ));
                }

                Ok(response.bytes().await.context("Failed to read response body")?.to_vec())
            },
            "downloading artifact",
        )
        .await
    }

    /// Cancel a proof request. This is only available in Mainnet (auction) mode.
    pub async fn cancel_request(&self, request_id: B256) -> Result<CancelRequestResponse> {
        match self.network_mode {
            NetworkMode::Mainnet => {
                self.with_retry(
                    || async {
                        let mut rpc = self.auction_prover_network_client().await?;
                        let nonce = self.get_nonce().await?;

                        let request_body = AuctionCancelRequestRequestBody {
                            nonce,
                            request_id: request_id.to_vec(),
                        };

                        let response = rpc
                            .cancel_request(AuctionCancelRequestRequest {
                                format: AuctionMessageFormat::Binary.into(),
                                signature: request_body.sign(&self.signer).await?,
                                body: Some(request_body),
                            })
                            .await?
                            .into_inner();

                        Ok(CancelRequestResponse::from(response))
                    },
                    "cancelling request",
                )
                .await
            }
            NetworkMode::Reserved => Ok(CancelRequestResponse::Unsupported),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::network::{signer::NetworkSigner, NetworkMode, RESERVED_RPC_URL};

    #[test]
    fn test_can_create_network_client_with_0x_bytes() {
        let private_key = hex::encode(alloy_signer_local::PrivateKeySigner::random().to_bytes());
        let signer = NetworkSigner::local(&private_key).unwrap();
        let _ = super::NetworkClient::new(signer, RESERVED_RPC_URL, NetworkMode::Reserved);
    }
}
