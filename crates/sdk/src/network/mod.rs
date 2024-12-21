//! # SP1 Network
//!
//! A library for interacting with the SP1 prover over the network.

pub mod client;
pub mod prover;
#[rustfmt::skip]
#[allow(missing_docs)]
#[allow(clippy::default_trait_access)]
#[allow(clippy::too_many_lines)]
pub mod proto;
pub mod builder;
mod error;
pub mod prove;
pub mod utils;

pub use error::*;

pub use crate::network::client::NetworkClient;
pub use crate::network::proto::network::FulfillmentStrategy;
// Re-export for verification key hash + request ID.
pub use alloy_primitives::B256;

/// The default RPC URL for the prover network.
pub(crate) const DEFAULT_NETWORK_RPC_URL: &str = "https://rpc.production.succinct.tools/";

/// The default timeout for the prover network (4 hours).
pub(crate) const DEFAULT_TIMEOUT_SECS: u64 = 14400;

/// The default cycle limit for the prover network (100M cycles).
///
/// This will only be used if both simulation is skipped and the cycle limit is not explicitly set.
pub(crate) const DEFAULT_CYCLE_LIMIT: u64 = 100_000_000;
