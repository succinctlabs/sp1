use bn::{CurveError, FieldError, GroupError};
use thiserror_no_std::Error;

#[derive(Error, Debug)]
pub enum Error {
    // Cryptographic Errors
    #[error("BSB22 Commitment number mismatch")]
    Bsb22CommitmentMismatch,
    #[error("Challenge already computed")]
    ChallengeAlreadyComputed,
    #[error("Challenge not found")]
    ChallengeNotFound,
    #[error("Previous challenge not computed")]
    PreviousChallengeNotComputed,
    #[error("Pairing check failed")]
    PairingCheckFailed,
    #[error("Invalid point in subgroup check")]
    InvalidPoint,

    // Arithmetic Errors
    #[error("Beyond the modulus")]
    BeyondTheModulus,
    #[error("Ell too large")]
    EllTooLarge,
    #[error("Inverse not found")]
    InverseNotFound,
    #[error("Opening linear polynomial mismatch")]
    OpeningPolyMismatch,

    // Input Errors
    #[error("DST too large")]
    DSTTooLarge,
    #[error("Invalid number of digests")]
    InvalidNumberOfDigests,
    #[error("Invalid witness")]
    InvalidWitness,
    #[error("Invalid x length")]
    InvalidXLength,
    #[error("Unexpected flag")]
    UnexpectedFlag,
    #[error("Invalid data")]
    InvalidData,

    // Conversion Errors
    #[error("Failed to get Fr from random bytes")]
    FailedToGetFrFromRandomBytes,
    #[error("Failed to get x")]
    FailedToGetX,
    #[error("Failed to get y")]
    FailedToGetY,

    // External Library Errors
    #[error("BN254 Field Error")]
    Field(FieldError),
    #[error("BN254 Group Error")]
    Group(GroupError),
    #[error("BN254 Curve Error")]
    Curve(CurveError),

    // SP1 Errors
    #[error("Invalid program vkey hash")]
    InvalidProgramVkeyHash,
}
