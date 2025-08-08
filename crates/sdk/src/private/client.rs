use std::{
    borrow::Cow,
    time::{Duration, SystemTime, UNIX_EPOCH},
    usize,
};

use alloy_primitives::B256;
use anyhow::Result;
use k256::ecdsa::SigningKey;
use reqwest_middleware::ClientWithMiddleware as HttpClientWithMiddleware;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{HashableKey, SP1ProvingKey, SP1VerifyingKey};
use tonic::{async_trait, transport::Channel, Code};
use tracing::instrument;

use crate::{
    network::{
        grpc,
        proto::artifact::ArtifactType,
        retry::{self, RetryableRpc, DEFAULT_RETRY_TIMEOUT},
        utils::{sign_raw, Signable},
        NetworkClient,
    },
    private::proto::{
        private_prover_client::PrivateProverClient, CreateProgramRequest, CreateProgramRequestBody,
        CreateProgramResponse, GetProofRequestStatusRequest, GetProofRequestStatusResponse,
        ProgramExistsRequest, RequestProofRequest, RequestProofRequestBody, RequestProofResponse,
    },
    SP1ProofMode,
};

/// A client for interacting with the TEE.
pub struct PrivateClient {
    pub(crate) signer: SigningKey,
    pub(crate) http: HttpClientWithMiddleware,
    pub(crate) network_client: NetworkClient,
    pub(crate) rpc_url: String,
}

#[async_trait]
impl RetryableRpc for PrivateClient {
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

impl PrivateClient {
    /// Creates a new [`PrivateClient`] with the given rpc url.
    pub fn new(private_key: impl ToString, rpc_url: impl ToString) -> Self {
        let pk = private_key.to_string();
        let private_key_bytes =
            hex::decode(pk.strip_prefix("0x").unwrap_or(&pk)).expect("Invalid private key");
        let signer = SigningKey::from_slice(&private_key_bytes).expect("Invalid private key");
        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(0)
            .pool_idle_timeout(Duration::from_secs(240))
            .build()
            .unwrap();
        let network_client = NetworkClient::new(pk, rpc_url.to_string());

        Self { signer, http: client.into(), network_client, rpc_url: rpc_url.to_string() }
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
    pub async fn register_program(&self, pk: &SP1ProvingKey) -> Result<B256> {
        let vk_hash = Self::get_vk_hash(&pk.vk)?;

        // Try to get the existing program.
        if self.program_exists(vk_hash).await? {
            // The program already exists.
            Ok(vk_hash)
        } else {
            // The program doesn't exist, create it.
            self.create_program(vk_hash, pk).await?;
            tracing::info!("Registered program {:?}", vk_hash);
            Ok(vk_hash)
        }
    }

    /// Attempts to get the program on the network.
    ///
    /// # Details
    /// Returns `None` if the program does not exist.
    #[instrument(level = "debug", skip(self))]
    pub async fn program_exists(&self, vk_hash: B256) -> Result<bool> {
        self.with_retry(
            || async {
                let mut rpc = self.private_prover_client().await?;
                match rpc.program_exists(ProgramExistsRequest { vk_hash: vk_hash.to_vec() }).await {
                    Ok(response) => Ok(response.into_inner().exists),
                    Err(status) if status.code() == Code::NotFound => Ok(false),
                    Err(e) => Err(e.into()),
                }
            },
            "getting program",
        )
        .await
    }

    /// Creates a new program on the network.
    #[instrument(level = "debug", skip(self, pk))]
    pub async fn create_program(
        &self,
        vk_hash: B256,
        pk: &SP1ProvingKey,
    ) -> Result<CreateProgramResponse> {
        // Create the program artifact.
        // Create the program artifact.
        let mut store = self.network_client.artifact_store_client().await?;
        let program_uri = self
            .network_client
            .create_artifact_with_content(&mut store, ArtifactType::Program, pk)
            .await?;

        // Send the request.
        self.with_retry(
            || async {
                tracing::debug!("Start create program");
                let mut rpc = self.private_prover_client().await?;

                let nonce = 1; // TODO: Update

                let request_body = CreateProgramRequestBody {
                    nonce,
                    vk_hash: vk_hash.to_vec(),
                    program_uri: program_uri.clone(),
                };

                let request = CreateProgramRequest {
                    signature: request_body.sign(&self.signer),
                    body: Some(request_body),
                };

                tracing::debug!("Send request");
                Ok(rpc.create_program(request).await?.into_inner())
            },
            "creating program",
        )
        .await
    }

    /// Get the status of a given proof.
    ///
    /// # Details
    /// If the status is Fulfilled, the proof is also returned.
    pub async fn get_proof_request_status(
        &self,
        request_id: B256,
        timeout: Option<Duration>,
    ) -> Result<GetProofRequestStatusResponse> {
        // Get the status.
        let response = self
            .with_retry_timeout(
                || async {
                    let mut rpc = self.private_prover_client().await?;
                    Ok(rpc
                        .get_proof_request_status(GetProofRequestStatusRequest {
                            request_id: request_id.to_vec(),
                        })
                        .await?
                        .into_inner())
                },
                timeout.unwrap_or(DEFAULT_RETRY_TIMEOUT),
                "getting proof request status",
            )
            .await?;

        tracing::debug!("End get proof request status");
        Ok(response)
    }

    /// Creates a proof request with the given verifying key hash and stdin.
    #[instrument(level = "debug", skip(self, stdin))]
    pub async fn request_proof(
        &self,
        vk_hash: B256,
        stdin: &SP1Stdin,
        mode: SP1ProofMode,
        timeout_secs: u64,
        cycle_limit: u64,
        gas_limit: u64,
    ) -> Result<RequestProofResponse> {
        // Calculate the deadline.
        let start = SystemTime::now();
        let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Invalid start time");
        let deadline = since_the_epoch.as_secs() + timeout_secs;

        // Send the request.
        self.with_retry(
            || async {
                let mut rpc = self.private_prover_client().await?;
                let request_body = RequestProofRequestBody {
                    nonce: todo!(),
                    vk_hash: vk_hash.to_vec(),
                    mode: todo!(), // mode.into(),
                    version: todo!(),
                    stdin_uri: todo!(),
                    cycle_limit,
                    gas_limit,
                    deadline,
                };

                // Serialize the body.
                let request = RequestProofRequest {
                    signature: sign(todo!(), &self.signer),
                    body: Some(request_body),
                };

                tracing::debug!("Sending request_proof");
                let request_response = rpc.request_proof(request).await?.into_inner();

                Ok(request_response)
            },
            "requesting proof",
        )
        .await
    }

    pub(crate) async fn private_prover_client(&self) -> Result<PrivateProverClient<Channel>> {
        self.with_retry(
            || async {
                match grpc::configure_endpoint(&self.rpc_url)?.connect().await {
                    Ok(channel) => {
                        Ok(PrivateProverClient::new(channel).max_decoding_message_size(usize::MAX))
                    }
                    Err(err) => {
                        tracing::error!("{err:#?}");
                        Err(err.into())
                    }
                }
            },
            "creating private client",
        )
        .await
    }
}

fn sign(message: &[u8], signer: &SigningKey) -> Vec<u8> {
    let (sig, v) = sign_raw(message, signer);
    let mut signature_bytes = sig.to_vec();
    signature_bytes.push(v.to_byte());

    signature_bytes
}
