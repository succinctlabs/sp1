use serde::{Deserialize, Serialize};
use sp1_prover::{worker::ProofFromNetwork, SP1VerifyingKey};
use sp1_prover_types::{network_base_types::ProofMode, SerializableRiscvMachine};

use crate::CudaClientError;
use sp1_core_machine::io::SP1Stdin;

#[derive(Serialize, Deserialize)]
pub enum Request {
    /// Tell the server to create a new proving key.
    Setup { elf: Vec<u8>, machine: SerializableRiscvMachine },

    /// Tell the server to create a proof with the given mode.
    ProveWithMode { mode: ProofMode, key: [u8; 32], stdin: SP1Stdin, proof_nonce: [u32; 4] },

    /// Tell the server to destroy a proving key.
    Destroy { key: [u8; 32] },
}

#[derive(Serialize, Deserialize)]
pub enum Response {
    /// The server has initialized.
    Ok,
    /// The setup response, containing the vkey and key id.
    Setup { id: [u8; 32], vk: SP1VerifyingKey },
    /// A generic proof that can be any of the proof types.
    Proof { proof: ProofFromNetwork },
    /// The server returned a prover error.
    ProverError(String),
    /// The error response, containing the error message.
    InternalError(String),
    /// The server has disconnected the client.
    ///
    /// This is really only useful for debugging purposes,
    /// if for some reason we dont send enoug bytes.
    ConnectionClosed,
}

impl Response {
    /// Get the type of the response.
    pub(crate) const fn type_of(&self) -> &'static str {
        match self {
            Response::Ok => "Ok",
            Response::Setup { .. } => "Setup",
            Response::Proof { .. } => "Proof",
            Response::InternalError(_) => "InternalError",
            Response::ProverError(_) => "ProverError",
            Response::ConnectionClosed => "ConnectionClosed",
        }
    }

    /// Capture any expected errors and convert them to a [`CudaClientError`].
    pub(crate) fn into_result(self) -> Result<Self, CudaClientError> {
        match self {
            Self::InternalError(e) => Err(CudaClientError::ServerError(e)),
            Self::ProverError(e) => {
                // todo!(n): can we make the [`SP1ProverError`] serde compatible?
                Err(CudaClientError::ServerError(e))
            }
            _ => Ok(self),
        }
    }
}
