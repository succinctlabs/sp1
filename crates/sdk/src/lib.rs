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

mod client;
mod prover;
mod verify;

pub mod artifacts;
pub mod install;

//#[cfg(feature = "cuda")]
//pub use crate::local::CudaProver;

#[cfg(feature = "network-v2")]
pub use crate::network_v2::NetworkProver;

#[cfg(feature = "network-v2")]
#[path = "network-v2/mod.rs"]
pub mod network_v2;

pub mod types;
pub use types::{
    Elf, Mode, ProofOpts, SP1ProvingKey, SP1ProofWithPublicValues, SP1VerifyingKey, SP1VerificationError
};

/// We wrap the `include_elf` macro to return an `Elf` type.
#[doc(hidden)]
pub use sp1_build::include_elf as _include_elf_inner;

/// Returns an [Elf] by the zkVM program target name.
///
/// Note that this only works when using `sp1_build::build_program` or
/// `sp1_build::build_program_with_args` in a build script.
///
/// By default, the program target name is the same as the program crate name. However, this might
/// not be the case for non-standard project structures. For example, placing the entrypoint source
/// file at `src/bin/my_entry.rs` would result in the program target being named `my_entry`, in
/// which case the invocation should be `include_elf!("my_entry")` instead.
#[macro_export]
macro_rules! include_elf {
    ($arg:tt) => {{
        let elf_slice = $crate::_include_elf_inner!($arg);

        $crate::types::Elf::Slice(elf_slice)
    }};
}

pub use sp1_core_executor::{ExecutionReport, HookEnv, SP1Context, SP1ContextBuilder};
pub use sp1_core_machine::{io::SP1Stdin, riscv::cost::CostEstimator, SP1_CIRCUIT_VERSION};
pub use sp1_primitives::io::SP1PublicValues;
pub use sp1_prover::{
    CoreSC, HashableKey, InnerSC, OuterSC, PlonkBn254Proof, ProverMode, SP1Prover,
};

/// The default timeout seconds for a proof request to be generated (4 hours).
///
pub const DEFAULT_TIMEOUT: u64 = 14400;

/// The default cycle limit for a proof request.
pub const DEFAULT_CYCLE_LIMIT: u64 = 100_000_000;
