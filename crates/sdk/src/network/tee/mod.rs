//! # TEE Integrity Proofs.
//!
//! An "integrity proof" is a signature over the outputs of the execution of a program computed
//! in a trusted execution environment (TEE).
//!
//! This acts a "2-factor authentication" for the SP1 proving system.

/// The API for the TEE server.
pub mod api;

/// The client for the TEE server.
pub mod client;

/// The type of TEE proof to use.
pub enum TEEProof {
    /// Use a Nitro TEE instance to create an integrity proof.
    NitroIntegrity,
    /// Do not create a TEE proof.
    None,
}

/// WIP docs todo improve
///
///
/// This method will get the list of signers for the TEE server, trusting the server to honestly
/// report the list of signers.
///
/// This is a convience method, if you want to actually verify attestions from the TEE server,
/// you need to build the Enclave image yourself, and use the provided functionality from the `sp1-tee`
/// crate to verify the signers you care about.
///
/// Signers may be cross checked from the on-chain state with attestaions stored in s3.
///
/// # Errors
/// - [`client::ClientError::Http`] - If the request fails to send.
pub async fn get_tee_signers(
    pcr0: Option<&str>,
) -> Result<Vec<alloy_primitives::Address>, client::ClientError> {
    let client = client::Client::default();

    client.get_signers(pcr0).await
}
