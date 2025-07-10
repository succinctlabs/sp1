use thiserror::Error;
use tonic::Status;

/// An error that can occur when interacting with the prover network.
#[derive(Error, Debug)]
pub enum Error {
    /// The program execution failed.
    #[error("Program simulation failed")]
    SimulationFailed,

    /// The proof request is unexecutable.
    #[error("Proof request 0x{} is unexecutable", hex::encode(.request_id))]
    RequestUnexecutable {
        /// The ID of the request that cannot be executed.
        request_id: Vec<u8>,
    },

    /// The proof request is unfulfillable.
    #[error("Proof request 0x{} is unfulfillable", hex::encode(.request_id))]
    RequestUnfulfillable {
        /// The ID of the request that cannot be fulfilled.
        request_id: Vec<u8>,
    },

    /// The proof request timed out.
    #[error("Proof request 0x{} timed out", hex::encode(.request_id))]
    RequestTimedOut {
        /// The ID of the request that timed out.
        request_id: Vec<u8>,
    },

    /// The proof request timed out waiting for a prover to bid on it.
    #[error("Proof request 0x{} timed out during the auction", hex::encode(.request_id))]
    RequestAuctionTimedOut {
        /// The ID of the request that timed out during auction.
        request_id: Vec<u8>,
    },

    /// An error occurred while interacting with the RPC server.
    #[error("RPC error")]
    RpcError(#[from] Status),

    /// An unknown error occurred.
    #[error("Other error: {0}")]
    Other(#[from] anyhow::Error),
}
