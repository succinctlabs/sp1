use bn::{CurveError, FieldError, GroupError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    // Input Errors
    #[error("Invalid witness")]
    InvalidWitness,
    #[error("Invalid x length")]
    InvalidXLength,
    #[error("Invalid data")]
    InvalidData,
    #[error("Invalid point in subgroup check")]
    InvalidPoint,

    // Conversion Errors
    #[error("Failed to get Fr from random bytes")]
    FailedToGetFrFromRandomBytes,

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
