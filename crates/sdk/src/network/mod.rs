//! # SP1 Network
//!
//! A library for interacting with the SP1 prover over the network.

pub mod client;
pub mod prover;
mod sign_message;
#[rustfmt::skip]
#[allow(missing_docs)]
#[allow(clippy::default_trait_access)]
#[allow(clippy::too_many_lines)]
pub mod proto;
pub mod builder;
pub mod prove;
pub mod utils;

pub use crate::network::client::NetworkClient;
pub use crate::network::proto::network::FulfillmentStrategy;

pub(crate) const DEFAULT_PROVER_NETWORK_RPC: &str = "https://rpc.production.succinct.tools/";
pub(crate) const DEFAULT_TIMEOUT_SECS: u64 = 14400;
pub(crate) const DEFAULT_CYCLE_LIMIT: u64 = 100_000_000;
