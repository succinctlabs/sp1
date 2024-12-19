//! # SP1 Network
//!
//! A library for interacting with the SP1 prover over the network.

pub mod client;
pub mod prover;
mod sign_message;
#[rustfmt::skip]
#[allow(missing_docs)]
pub mod proto;
pub mod builder;
pub mod prove;
pub mod utils;

pub(crate) const DEFAULT_PROVER_NETWORK_RPC: &str = "https://rpc.production.succinct.tools/";
pub(crate) const DEFAULT_TIMEOUT_SECS: u64 = 14400;
pub(crate) const DEFAULT_CYCLE_LIMIT: u64 = 100_000_000;
