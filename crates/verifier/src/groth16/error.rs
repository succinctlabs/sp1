use thiserror_no_std::Error;

#[derive(Debug, Error)]
pub enum Groth16Error {
    #[error("Proof verification failed")]
    ProofVerificationFailed,
    #[error("Process verifying key failed")]
    ProcessVerifyingKeyFailed,
    #[error("Prepare inputs failed")]
    PrepareInputsFailed,
    #[error("Unexpected identity")]
    UnexpectedIdentity,
    #[error("General error")]
    GeneralError(#[from] crate::error::Error),
    #[error("Groth16 vkey hash mismatch")]
    Groth16VkeyHashMismatch,
}
