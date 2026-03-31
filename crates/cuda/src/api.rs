use std::sync::Arc;

use serde::de::Deserializer;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use sp1_core_machine::autoprecompiles::Sp1Apc;
use sp1_core_machine::riscv::RiscvAir;
use sp1_hypercube::Machine;
use sp1_primitives::SP1Field;
use sp1_prover::{worker::ProofFromNetwork, SP1VerifyingKey};

use sp1_prover_types::network_base_types::ProofMode;

use crate::CudaClientError;
use sp1_core_machine::io::SP1Stdin;

/// A wrapper around `Machine<SP1Field, RiscvAir<SP1Field>>` with custom serde.
///
/// Only the APCs are serialized; the base machine is reconstructed via
/// `RiscvAir::machine_with_apcs()` on deserialization.
///
/// This can't live in `sp1-hypercube` (where `Machine` is defined) because
/// deserialization depends on `RiscvAir` from `sp1-core-machine`, creating a circular dependency.
pub struct SerializableMachine(pub Machine<SP1Field, RiscvAir<SP1Field>>);

impl Serialize for SerializableMachine {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let apcs: Vec<_> = self
            .0
            .chips()
            .iter()
            .filter_map(|chip| match chip.air.as_ref() {
                RiscvAir::Apc(apc_chip) => Some(apc_chip.apc().clone()),
                _ => None,
            })
            .collect();
        // Serialize APCs via JSON first, then send the JSON bytes through bincode.
        // This is necessary because powdr's `AlgebraicExpression` uses `#[serde(untagged)]`,
        // which requires `deserialize_any` — unsupported by bincode.
        let json_bytes =
            serde_json::to_vec(&apcs).map_err(|e| serde::ser::Error::custom(e.to_string()))?;
        json_bytes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SerializableMachine {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let json_bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        let apcs: Vec<Arc<Sp1Apc<SP1Field>>> = serde_json::from_slice(&json_bytes)
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        Ok(Self(RiscvAir::machine_with_apcs(apcs)))
    }
}

#[derive(Serialize, Deserialize)]
pub enum Request {
    /// Tell the server to create a new proving key.
    Setup { elf: Vec<u8>, machine: SerializableMachine },

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
