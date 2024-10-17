//! # SP1 SDK
//!
//! A library for interacting with the SP1 RISC-V zkVM.
//!
//! Visit the [Getting Started](https://succinctlabs.github.io/sp1/getting-started.html) section
//! in the official SP1 documentation for a quick start guide.
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
mod std;

#[cfg(feature = "std")]
pub use std::*;
