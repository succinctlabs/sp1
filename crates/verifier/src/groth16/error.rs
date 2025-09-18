use thiserror::Error;

#[derive(Debug, Error)]
pub enum Groth16Error {
    #[error("Proof verification failed")]
    ProofVerificationFailed,
    #[error("Process verifying key failed")]
    ProcessVerifyingKeyFailed,
    #[error("Prepare inputs failed")]
    PrepareInputsFailed,
    #[error("General error: {0}")]
    GeneralError(#[from] crate::error::Error),
    #[error("Groth16 vkey hash mismatch")]
    Groth16VkeyHashMismatch,
}
