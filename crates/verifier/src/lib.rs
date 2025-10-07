//! This crate provides verifiers for SP1 Groth16 and Plonk BN254 proofs in a no-std environment.
//! It is patched for efficient verification within the SP1 zkVM context.

#![cfg_attr(not(any(feature = "std", test)), no_std)]
extern crate alloc;

use lazy_static::lazy_static;

lazy_static! {
    /// The PLONK verifying key for this SP1 version.
    pub static ref PLONK_VK_BYTES: &'static [u8] = include_bytes!("../bn254-vk/plonk_vk.bin");
}

lazy_static! {
    /// The Groth16 verifying key for this SP1 version.
    pub static ref GROTH16_VK_BYTES: &'static [u8] = include_bytes!("../bn254-vk/groth16_vk.bin");
}

#[cfg(feature = "compressed")]
pub mod compressed;
#[cfg(feature = "compressed")]
pub use compressed::{CompressedError, CompressedVerifier};

mod constants;
pub mod converter;
mod error;

mod utils;
pub use utils::*;

pub use groth16::{converter::*, error::Groth16Error, Groth16Verifier};
mod groth16;

#[cfg(feature = "ark")]
pub use groth16::ark_converter::*;

pub use plonk::{error::PlonkError, PlonkVerifier};
mod plonk;

#[cfg(test)]
mod tests;
