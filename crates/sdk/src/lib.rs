//! # SP1 SDK
//!
//! A library for interacting with the SP1 RISC-V zkVM.
//!
//! Visit the [Getting Started](https://succinctlabs.github.io/sp1/getting-started.html) section
//! in the official SP1 documentation for a quick start guide.

mod client;
mod mode;
mod opts;
mod prover;
mod request;
mod verify;

pub mod artifacts;
pub mod install;

#[path = "network-v2/mod.rs"]
pub mod network_v2;

#[cfg(feature = "cuda")]
pub use crate::local::CudaProver;
#[cfg(feature = "network-v2")]
pub use crate::network_v2::NetworkProver;

pub mod local;
pub mod proof;
pub mod utils {
    pub use sp1_core_machine::utils::setup_logger;
}

pub use client::*;
pub use local::SP1VerificationError;
pub use proof::*;

// pub use local::{LocalProver, MockProver, Prover};

pub use sp1_build::include_elf;
pub use sp1_core_executor::{ExecutionReport, HookEnv, SP1Context, SP1ContextBuilder};
pub use sp1_core_machine::{io::SP1Stdin, riscv::cost::CostEstimator, SP1_CIRCUIT_VERSION};
pub use sp1_primitives::io::SP1PublicValues;
pub use sp1_prover::{
    CoreSC, HashableKey, InnerSC, OuterSC, PlonkBn254Proof, ProverMode, SP1Prover, SP1ProvingKey,
    SP1VerifyingKey,
};
