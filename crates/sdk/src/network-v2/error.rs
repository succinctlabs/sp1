use thiserror::Error;
use tonic::Status;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Simulation failed")]
    SimulationFailed,

    #[error("Proof request is unexecutable")]
    RequestUnexecutable,

    #[error("Proof request is unfulfillable")]
    RequestUnfulfillable,

    #[error("Proof request timed out")]
    RequestTimedOut,

    #[error("Artifact upload failed: {message}")]
    ArtifactUpload { message: String },

    #[error("Artifact download failed: {message}")]
    ArtifactDownload { message: String },

    #[error("RPC error")]
    RpcError(#[from] Status),

    #[error("Other error: {0}")]
    Other(#[from] anyhow::Error),
}
