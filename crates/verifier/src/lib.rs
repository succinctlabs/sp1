//! This crate provides verifiers for SP1 Groth16 and Plonk BN254 proofs in a no-std environment.
//! It is patched for efficient verification within the SP1 zkVM context.

#![cfg_attr(not(any(feature = "std", test)), no_std)]
extern crate alloc;

use lazy_static::lazy_static;
use slop_algebra::PrimeField;
use sp1_hypercube::koalabears_to_bn254;

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
    /// Derived from the recursion verifying key data.
    pub static ref VK_ROOT_BYTES: [u8; 32] = {
        let vks = recursion_vks::VerifierRecursionVks::default();
        let bn254 = koalabears_to_bn254(&vks.root());
        let bigint = bn254.as_canonical_biguint();
        let be_bytes = bigint.to_bytes_be();
        let mut result = [0u8; 32];
        let start = 32 - be_bytes.len();
        result[start..].copy_from_slice(&be_bytes);
        result
    };
}

mod recursion_vks;
pub use recursion_vks::VerifierRecursionVks;

pub mod compressed;

mod constants;
pub mod converter;
mod error;
mod proof;

mod utils;
pub use utils::*;

pub use groth16::{error::Groth16Error, Groth16Verifier};
pub use proof::*;
mod groth16;

#[cfg(feature = "ark")]
pub use groth16::ark_converter::*;

pub use plonk::{error::PlonkError, PlonkVerifier};
mod plonk;

#[cfg(test)]
mod tests;
