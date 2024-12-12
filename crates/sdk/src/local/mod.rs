#[cfg(feature = "cuda")]
mod cuda;
mod mock;
mod prover;

#[cfg(feature = "cuda")]
pub use cuda::CudaProver;

pub use prover::*;


use sp1_prover::{
    CoreSC, InnerSC,
};
use sp1_stark::MachineVerificationError;
use strum_macros::EnumString;
use thiserror::Error;


/// The type of prover.
#[derive(Debug, PartialEq, EnumString)]
pub enum ProverType {
    Local,
    Cuda,
    Mock,
    Network,
}

#[derive(Error, Debug)]
pub enum SP1VerificationError {
    #[error("Invalid public values")]
    InvalidPublicValues,
    #[error("Version mismatch")]
    VersionMismatch(String),
    #[error("Core machine verification error: {0}")]
    Core(MachineVerificationError<CoreSC>),
    #[error("Recursion verification error: {0}")]
    Recursion(MachineVerificationError<InnerSC>),
    #[error("Plonk verification error: {0}")]
    Plonk(anyhow::Error),
    #[error("Groth16 verification error: {0}")]
    Groth16(anyhow::Error),
}
