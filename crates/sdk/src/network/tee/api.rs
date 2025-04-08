use crate::SP1Stdin;
use alloy_primitives::{Address, PrimitiveSignature};
use alloy_signer::SignerSync;
use serde::{Deserialize, Serialize};

use k256::ecdsa::Signature;

/// The request payload for the TEE server.
#[derive(Debug, Serialize, Deserialize)]
pub struct TEERequest {
    /// The network request id.
    pub id: [u8; 32],
    /// The program to execute.
    pub program: Vec<u8>,
    /// The cycle limit for the program.
    pub cycle_limit: u64,
    /// The stdin for the program.
    pub stdin: SP1Stdin,
    /// The signature of the request id.
    pub signature: PrimitiveSignature,
}

impl TEERequest {
    /// The selector for the TEE verifier.
    pub(crate) fn new<S: SignerSync>(
        signer: &S,
        id: [u8; 32],
        program: Vec<u8>,
        stdin: SP1Stdin,
        cycle_limit: u64,
    ) -> Self {
        let signature = signer.sign_message_sync(&id).expect("Failed to sign request id");

        Self { id, program, cycle_limit, stdin, signature }
    }
}

/// The response payload from the TEE server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TEEResponse {
    /// The vkey computed by the TEE server.
    pub vkey: [u8; 32],
    /// The public values computed by the TEE server.
    pub public_values: Vec<u8>,
    /// The signature over the public values and the vkey.
    /// Computed as keccak256([`keccack256(version)` || `vkey` || `keccack256(public_values)`]).
    pub signature: Signature,
    /// The recovery id computed by the TEE server.
    pub recovery_id: u8,
}

impl TEEResponse {
    /// The bytes to prepend to the encoded proof bytes.
    #[must_use]
    pub fn as_prefix_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Include the version of the SP1 circuit.
        let version_bytes = super::SP1_TEE_VERSION.to_le_bytes();

        // The length of the version bytes, panics if the length is greater than 255.
        let version_bytes_len: u8 = version_bytes.len().try_into().unwrap();

        // Push the selector
        bytes.extend_from_slice(&Self::selector());
        // Push v.
        bytes.extend_from_slice(&self.recovery_id.to_be_bytes());
        // Push r and s.
        bytes.extend_from_slice(&self.signature.to_bytes());
        // Push the version bytes length.
        bytes.push(version_bytes_len);
        // Push the version bytes.
        bytes.extend_from_slice(&version_bytes);

        bytes
    }

    /// The selector for the TEE verifier.
    fn selector() -> [u8; 4] {
        alloy_primitives::keccak256("SP1TeeVerifier")[0..4].try_into().unwrap()
    }
}

/// The response payload from the TEE server for the `get_address` endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetAddressResponse {
    /// The address of the TEE signer.
    pub address: Address,
}

/// The underlying payload for the SSE event sent from the TEE server.
///
/// This is an implementation detail, and should not be used directly.
#[derive(Debug, Serialize, Deserialize)]
pub enum EventPayload {
    /// The request was successful.
    Success(TEEResponse),
    /// The execution failed.
    Error(String),
}
