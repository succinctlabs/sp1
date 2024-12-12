use thiserror::Error;
use tonic::Status;

use crate::network_v2::types::RequestId;

/// An error that can occur when interacting with the prover network.
#[derive(Error, Debug)]
pub enum Error {
    #[error("Program simulation failed")]
    SimulationFailed,

    #[error("Proof request {request_id} is unexecutable")]
    RequestUnexecutable { request_id: RequestId },

    #[error("Proof request {request_id} is unfulfillable")]
    RequestUnfulfillable { request_id: RequestId },

    #[error("Proof request {request_id} deadline exceeded")]
    RequestDeadlineExceeded { request_id: RequestId },

    #[error("Artifact upload failed: {message}")]
    ArtifactUpload { message: String },

    #[error("Artifact download failed: {message}")]
    ArtifactDownload { message: String },

    #[error("RPC error")]
    RpcError(#[from] Status),

    #[error("Other error: {0}")]
    Other(#[from] anyhow::Error),
}
