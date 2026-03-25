pub mod build;
mod components;
pub mod recursion;
pub mod shapes;
mod types;
pub mod utils;
pub mod verify;
pub mod worker;

pub use types::*;

pub use components::*;

/// The global version for all components of SP1.
///
/// This string should be updated whenever any step in verifying an SP1 proof changes, including
/// core, recursion, and plonk-bn254. This string is used to download SP1 artifacts and the gnark
/// docker image.
pub const SP1_CIRCUIT_VERSION: &str = include_str!("../SP1_CIRCUIT_VERSION");

pub use sp1_hypercube::{HashableKey, SP1VerifyingKey};
