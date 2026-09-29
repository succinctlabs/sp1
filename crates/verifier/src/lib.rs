//! This crate provides verifiers for SP1 proofs in a `no_std` environment.
//!
//! Groth16 and Plonk verification are always available. Compressed proof types and verification
//! require the default `full` feature.

#![cfg_attr(not(any(feature = "std", test)), no_std)]
extern crate alloc;

use lazy_static::lazy_static;

lazy_static! {
    /// The PLONK verifying key for this SP1 version.
    pub static ref PLONK_VK_BYTES: &'static [u8] = include_bytes!("../vk-artifacts/plonk_vk.bin");
}

lazy_static! {
    /// The Groth16 verifying key for this SP1 version.
    pub static ref GROTH16_VK_BYTES: &'static [u8] = include_bytes!("../vk-artifacts/groth16_vk.bin");
}

lazy_static! {
    /// The VK merkle tree root as 32 bytes (big-endian bn254 representation).
    /// Precomputed from the recursion verifying key data for this SP1 version.
    pub static ref VK_ROOT_BYTES: [u8; 32] = [
        0x00, 0x2f, 0x85, 0x0e, 0xe9, 0x98, 0x97, 0x4d, 0x6c, 0xc0, 0x0e, 0x50, 0xcd, 0x08,
        0x14, 0xb0, 0x98, 0xc0, 0x5b, 0xfa, 0xde, 0x46, 0x6d, 0x28, 0x57, 0x32, 0x40, 0xd0,
        0x57, 0xf2, 0x53, 0x52,
    ];
}

#[cfg(feature = "full")]
mod recursion_vks;
#[cfg(feature = "full")]
pub use recursion_vks::VerifierRecursionVks;

#[cfg(feature = "full")]
pub mod compressed;

mod constants;
pub mod converter;
mod error;
#[cfg(feature = "full")]
mod proof;

mod utils;
pub use utils::*;

pub use groth16::{error::Groth16Error, Groth16Verifier};
#[cfg(feature = "full")]
pub use proof::*;
mod groth16;

#[cfg(feature = "ark")]
pub use groth16::ark_converter::*;

pub use plonk::{error::PlonkError, PlonkVerifier};
mod plonk;

#[cfg(all(test, feature = "full"))]
mod tests;
