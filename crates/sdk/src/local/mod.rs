#[cfg(feature = "cuda")]
mod cuda;
mod mock;
mod prover;

#[cfg(feature = "cuda")]
pub use cuda::CudaProver;

pub use prover::*;

use itertools::Itertools;
use p3_field::PrimeField32;
use std::borrow::Borrow;

use anyhow::Result;
use sp1_core_executor::SP1Context;
use sp1_core_machine::{io::SP1Stdin, SP1_CIRCUIT_VERSION};
use sp1_prover::{
    components::SP1ProverComponents, CoreSC, InnerSC, SP1CoreProofData, SP1Prover, SP1ProvingKey,
    SP1VerifyingKey,
};
use sp1_stark::{air::PublicValues, MachineVerificationError, Word};
use strum_macros::EnumString;
use thiserror::Error;

use crate::install::try_install_circuit_artifacts;
use crate::opts::ProofOpts;
use crate::{proof::SP1Proof, proof::SP1ProofKind, proof::SP1ProofWithPublicValues};

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
