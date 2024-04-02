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
    UnspecifiedStatus = 0,
    Created = 1,
    Pending = 2,
    Running = 3,
    Succeeded = 4,
    Failed = 5,
}
impl ProofStatus {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ProofStatus::UnspecifiedStatus => "UNSPECIFIED_STATUS",
            ProofStatus::Created => "CREATED",
            ProofStatus::Pending => "PENDING",
            ProofStatus::Running => "RUNNING",
            ProofStatus::Succeeded => "SUCCEEDED",
            ProofStatus::Failed => "FAILED",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "UNSPECIFIED_STATUS" => Some(Self::UnspecifiedStatus),
            "CREATED" => Some(Self::Created),
            "PENDING" => Some(Self::Pending),
            "RUNNING" => Some(Self::Running),
            "SUCCEEDED" => Some(Self::Succeeded),
            "FAILED" => Some(Self::Failed),
            _ => None,
        }
    }
}
pub const SERVICE_FQN: &str = "/prover.SP1ProverService";
#[twirp::async_trait::async_trait]
pub trait Sp1ProverService {
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
}
pub fn router<T>(api: std::sync::Arc<T>) -> twirp::Router
where
    T: Sp1ProverService + Send + Sync + 'static,
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
        .build()
}
#[twirp::async_trait::async_trait]
pub trait Sp1ProverServiceClient: Send + Sync + std::fmt::Debug {
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
}
#[twirp::async_trait::async_trait]
impl Sp1ProverServiceClient for twirp::client::Client {
    async fn create_proof(
        &self,
        req: CreateProofRequest,
    ) -> Result<CreateProofResponse, twirp::ClientError> {
        let url = self.base_url.join("prover.SP1ProverService/CreateProof")?;
        self.request(url, req).await
    }
    async fn submit_proof(
        &self,
        req: SubmitProofRequest,
    ) -> Result<SubmitProofResponse, twirp::ClientError> {
        let url = self.base_url.join("prover.SP1ProverService/SubmitProof")?;
        self.request(url, req).await
    }
    async fn get_proof_status(
        &self,
        req: GetProofStatusRequest,
    ) -> Result<GetProofStatusResponse, twirp::ClientError> {
        let url = self
            .base_url
            .join("prover.SP1ProverService/GetProofStatus")?;
        self.request(url, req).await
    }
}
