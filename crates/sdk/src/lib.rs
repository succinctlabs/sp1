//! # SP1 SDK
//!
//! A library for interacting with the SP1 RISC-V zkVM.
//!
//! Visit the [Getting Started](https://succinctlabs.github.io/sp1/getting-started.html) section
//! in the official SP1 documentation for a quick start guide.

pub mod local;
pub mod proof;
pub mod utils {
    pub use sp1_core_machine::utils::setup_logger;
}

pub use client::*;
pub use proof::*;

pub use sp1_build::include_elf;
pub use sp1_core_executor::{ExecutionReport, HookEnv, SP1Context, SP1ContextBuilder};
pub use sp1_core_machine::{io::SP1Stdin, riscv::cost::CostEstimator, SP1_CIRCUIT_VERSION};
pub use sp1_primitives::io::SP1PublicValues;
pub use sp1_prover::{
    CoreSC, HashableKey, InnerSC, OuterSC, PlonkBn254Proof, ProverMode, SP1Prover, SP1ProvingKey,
    SP1VerifyingKey,
};

use sp1_stark::MachineVerificationError;
use thiserror::Error;

mod client;
mod prover;
mod verify;

pub mod artifacts;
pub mod install;

#[cfg(feature = "cuda")]
pub use crate::local::CudaProver;

#[cfg(feature = "network-v2")]
pub use crate::network_v2::NetworkProver;

#[cfg(feature = "network-v2")]
#[path = "network-v2/mod.rs"]
pub mod network_v2;
/// The default timeout seconds for a proof request to be generated (4 hours).
///
pub const DEFAULT_TIMEOUT: u64 = 14400;

/// The default cycle limit for a proof request.
pub const DEFAULT_CYCLE_LIMIT: u64 = 100_000_000;

pub struct ProofOpts {
    pub mode: Mode,
    pub timeout: u64,
    pub cycle_limit: u64,
}

impl Default for ProofOpts {
    fn default() -> Self {
        Self { mode: Mode::default(), timeout: DEFAULT_TIMEOUT, cycle_limit: DEFAULT_CYCLE_LIMIT }
    }
}

#[cfg(feature = "network-v2")]
use crate::network_v2::ProofMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Core,
    Compressed,
    Plonk,
    Groth16,
}

impl Default for Mode {
    fn default() -> Self {
        Self::Groth16
    }
}

#[cfg(feature = "network-v2")]
impl From<Mode> for ProofMode {
    fn from(value: Mode) -> Self {
        match value {
            Mode::Core => Self::Core,
            Mode::Compressed => Self::Compressed,
            Mode::Plonk => Self::Plonk,
            Mode::Groth16 => Self::Groth16,
        }
    }
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
