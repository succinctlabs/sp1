//! SP1 Groth16 and Plonk BN254 proof verifiers.
//!
//! Both Groth16 and PLONK verifiers are available by default (WASM-compatible).
//! Enable the `full` feature for compressed proofs and recursion VK support.

#![cfg_attr(not(any(feature = "std", test)), no_std)]
extern crate alloc;

#[cfg(feature = "full")]
use lazy_static::lazy_static;
#[cfg(feature = "full")]
use slop_algebra::PrimeField;
#[cfg(feature = "full")]
use sp1_hypercube::koalabears_to_bn254;

#[cfg(feature = "full")]
lazy_static! {
    /// The VK merkle tree root (dynamically computed from recursion VKs).
    pub static ref VK_ROOT_BYTES_DYNAMIC: [u8; 32] = {
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

#[cfg(feature = "full")]
mod recursion_vks;
#[cfg(feature = "full")]
pub use recursion_vks::VerifierRecursionVks;

#[cfg(feature = "full")]
pub mod compressed;

#[cfg(feature = "full")]
mod proof;
#[cfg(feature = "full")]
pub use proof::*;

pub use groth16::{error::Groth16Error, Groth16Verifier};
mod groth16;

#[cfg(feature = "ark")]
pub use groth16::ark_converter::*;

mod constants;
pub mod converter;
pub mod error;
mod utils;
pub use utils::*;

pub use plonk::{error::PlonkError, PlonkVerifier};
mod plonk;

/// The PLONK verifying key for SP1 v6.0.2.
pub static PLONK_VK_BYTES: &[u8] = include_bytes!("../vk-artifacts/plonk_vk.bin");

/// The Groth16 verifying key for SP1 v6.0.2.
pub static GROTH16_VK_BYTES: &[u8] = include_bytes!("../vk-artifacts/groth16_vk.bin");

/// The VK merkle tree root for SP1 v6.0.2 (precomputed).
/// Available in all contexts including no_std/WASM.
pub const VK_ROOT_BYTES: [u8; 32] = [
    0x00, 0x8c, 0xd5, 0x6e, 0x10, 0xc2, 0xfe, 0x24, 0x79, 0x5c, 0xff, 0x1e, 0x1d, 0x1f, 0x40, 0xd3,
    0xa3, 0x24, 0x52, 0x8d, 0x31, 0x56, 0x74, 0xda, 0x45, 0xd2, 0x6a, 0xfb, 0x37, 0x6e, 0x86, 0x70,
];

#[cfg(test)]
mod tests;
