#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateProofRequest {}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateProofResponse {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub program_put_url: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub stdin_put_url: ::prost::alloc::string::String,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubmitProofRequest {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubmitProofResponse {}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetProofStatusRequest {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetProofStatusResponse {
    #[prost(enumeration = "ProofStatus", tag = "1")]
    pub status: i32,
    #[prost(string, tag = "2")]
    pub result_get_url: ::prost::alloc::string::String,
    #[prost(uint32, tag = "3")]
    pub stage: u32,
    #[prost(uint32, tag = "4")]
    pub total_stages: u32,
    #[prost(string, tag = "5")]
    pub stage_name: ::prost::alloc::string::String,
    #[prost(uint32, optional, tag = "6")]
    pub stage_progress: ::core::option::Option<u32>,
    #[prost(uint32, optional, tag = "7")]
    pub stage_total: ::core::option::Option<u32>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RelayProofRequest {
    #[prost(string, tag = "1")]
    pub proof_id: ::prost::alloc::string::String,
    #[prost(uint32, tag = "2")]
    pub chain_id: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub verifier: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub callback: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub callback_data: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RelayProofResponse {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetRelayStatusRequest {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetRelayStatusResponse {
    #[prost(enumeration = "TransactionStatus", tag = "1")]
    pub status: i32,
    #[prost(bytes = "vec", tag = "2")]
    pub tx_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, tag = "3")]
    pub simulation_url: ::prost::alloc::string::String,
}
#[derive(
    serde::Serialize,
    serde::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    ::prost::Enumeration,
)]
#[repr(i32)]
pub enum ProofStatus {
    ProofUnspecifiedStatus = 0,
    ProofCreated = 1,
    ProofPending = 2,
    ProofRunning = 3,
    ProofSucceeded = 4,
    ProofFailed = 5,
}
impl ProofStatus {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ProofStatus::ProofUnspecifiedStatus => "PROOF_UNSPECIFIED_STATUS",
            ProofStatus::ProofCreated => "PROOF_CREATED",
            ProofStatus::ProofPending => "PROOF_PENDING",
            ProofStatus::ProofRunning => "PROOF_RUNNING",
            ProofStatus::ProofSucceeded => "PROOF_SUCCEEDED",
            ProofStatus::ProofFailed => "PROOF_FAILED",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "PROOF_UNSPECIFIED_STATUS" => Some(Self::ProofUnspecifiedStatus),
            "PROOF_CREATED" => Some(Self::ProofCreated),
            "PROOF_PENDING" => Some(Self::ProofPending),
            "PROOF_RUNNING" => Some(Self::ProofRunning),
            "PROOF_SUCCEEDED" => Some(Self::ProofSucceeded),
            "PROOF_FAILED" => Some(Self::ProofFailed),
            _ => None,
        }
    }
}
#[derive(
    serde::Serialize,
    serde::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    ::prost::Enumeration,
)]
#[repr(i32)]
pub enum TransactionStatus {
    TransactionUnspecifiedStatus = 0,
    TransactionScheduled = 1,
    TransactionBroadcasted = 2,
    TransactionTimedout = 3,
    TransactionFailed = 4,
    TransactionFinalized = 5,
}
impl TransactionStatus {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            TransactionStatus::TransactionUnspecifiedStatus => "TRANSACTION_UNSPECIFIED_STATUS",
            TransactionStatus::TransactionScheduled => "TRANSACTION_SCHEDULED",
            TransactionStatus::TransactionBroadcasted => "TRANSACTION_BROADCASTED",
            TransactionStatus::TransactionTimedout => "TRANSACTION_TIMEDOUT",
            TransactionStatus::TransactionFailed => "TRANSACTION_FAILED",
            TransactionStatus::TransactionFinalized => "TRANSACTION_FINALIZED",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "TRANSACTION_UNSPECIFIED_STATUS" => Some(Self::TransactionUnspecifiedStatus),
            "TRANSACTION_SCHEDULED" => Some(Self::TransactionScheduled),
            "TRANSACTION_BROADCASTED" => Some(Self::TransactionBroadcasted),
            "TRANSACTION_TIMEDOUT" => Some(Self::TransactionTimedout),
            "TRANSACTION_FAILED" => Some(Self::TransactionFailed),
            "TRANSACTION_FINALIZED" => Some(Self::TransactionFinalized),
            _ => None,
        }
    }
}
pub const SERVICE_FQN: &str = "/network.NetworkService";
#[twirp::async_trait::async_trait]
pub trait NetworkService {
    async fn create_proof(
        &self,
        ctx: twirp::Context,
        req: CreateProofRequest,
    ) -> Result<CreateProofResponse, twirp::TwirpErrorResponse>;
    async fn submit_proof(
        &self,
        ctx: twirp::Context,
        req: SubmitProofRequest,
    ) -> Result<SubmitProofResponse, twirp::TwirpErrorResponse>;
    async fn get_proof_status(
        &self,
        ctx: twirp::Context,
        req: GetProofStatusRequest,
    ) -> Result<GetProofStatusResponse, twirp::TwirpErrorResponse>;
    async fn relay_proof(
        &self,
        ctx: twirp::Context,
        req: RelayProofRequest,
    ) -> Result<RelayProofResponse, twirp::TwirpErrorResponse>;
    async fn get_relay_status(
        &self,
        ctx: twirp::Context,
        req: GetRelayStatusRequest,
    ) -> Result<GetRelayStatusResponse, twirp::TwirpErrorResponse>;
}
pub fn router<T>(api: std::sync::Arc<T>) -> twirp::Router
where
    T: NetworkService + Send + Sync + 'static,
{
    twirp::details::TwirpRouterBuilder::new(api)
        .route(
            "/CreateProof",
            |api: std::sync::Arc<T>, ctx: twirp::Context, req: CreateProofRequest| async move {
                api.create_proof(ctx, req).await
            },
        )
        .route(
            "/SubmitProof",
            |api: std::sync::Arc<T>, ctx: twirp::Context, req: SubmitProofRequest| async move {
                api.submit_proof(ctx, req).await
            },
        )
        .route(
            "/GetProofStatus",
            |api: std::sync::Arc<T>, ctx: twirp::Context, req: GetProofStatusRequest| async move {
                api.get_proof_status(ctx, req).await
            },
        )
        .route(
            "/RelayProof",
            |api: std::sync::Arc<T>, ctx: twirp::Context, req: RelayProofRequest| async move {
                api.relay_proof(ctx, req).await
            },
        )
        .route(
            "/GetRelayStatus",
            |api: std::sync::Arc<T>, ctx: twirp::Context, req: GetRelayStatusRequest| async move {
                api.get_relay_status(ctx, req).await
            },
        )
        .build()
}
#[twirp::async_trait::async_trait]
pub trait NetworkServiceClient: Send + Sync + std::fmt::Debug {
    async fn create_proof(
        &self,
        req: CreateProofRequest,
    ) -> Result<CreateProofResponse, twirp::ClientError>;
    async fn submit_proof(
        &self,
        req: SubmitProofRequest,
    ) -> Result<SubmitProofResponse, twirp::ClientError>;
    async fn get_proof_status(
        &self,
        req: GetProofStatusRequest,
    ) -> Result<GetProofStatusResponse, twirp::ClientError>;
    async fn relay_proof(
        &self,
        req: RelayProofRequest,
    ) -> Result<RelayProofResponse, twirp::ClientError>;
    async fn get_relay_status(
        &self,
        req: GetRelayStatusRequest,
    ) -> Result<GetRelayStatusResponse, twirp::ClientError>;
}
#[twirp::async_trait::async_trait]
impl NetworkServiceClient for twirp::client::Client {
    async fn create_proof(
        &self,
        req: CreateProofRequest,
    ) -> Result<CreateProofResponse, twirp::ClientError> {
        let url = self.base_url.join("network.NetworkService/CreateProof")?;
        self.request(url, req).await
    }
    async fn submit_proof(
        &self,
        req: SubmitProofRequest,
    ) -> Result<SubmitProofResponse, twirp::ClientError> {
        let url = self.base_url.join("network.NetworkService/SubmitProof")?;
        self.request(url, req).await
    }
    async fn get_proof_status(
        &self,
        req: GetProofStatusRequest,
    ) -> Result<GetProofStatusResponse, twirp::ClientError> {
        let url = self
            .base_url
            .join("network.NetworkService/GetProofStatus")?;
        self.request(url, req).await
    }
    async fn relay_proof(
        &self,
        req: RelayProofRequest,
    ) -> Result<RelayProofResponse, twirp::ClientError> {
        let url = self.base_url.join("network.NetworkService/RelayProof")?;
        self.request(url, req).await
    }
    async fn get_relay_status(
        &self,
        req: GetRelayStatusRequest,
    ) -> Result<GetRelayStatusResponse, twirp::ClientError> {
        let url = self
            .base_url
            .join("network.NetworkService/GetRelayStatus")?;
        self.request(url, req).await
    }
}
