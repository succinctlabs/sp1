use serde::{Deserialize, Serialize};

use crate::SyscallCode;

/// Allowed presets for collections of events that may be retained instead of deferred.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RetainedEventsPreset {
    /// Retain events for BLS12-381 base field arithmetic operations.
    Bls12381Field,
    /// Retain events for BN254 base field arithmetic operations.
    Bn254Field,
    /// Retain events for SHA-256 operations.
    Sha256,
    /// Retain events for Poseidon2 operations.
    Poseidon2,
    /// Retain events for ``U256Ops`` operations.
    U256Ops,
    /// Retain events for Secp256k1 operations.
    Secp256k1,
    /// Retain events for Keccak operations.
    Keccak,
}

impl RetainedEventsPreset {
    /// The codes of syscalls that generate events that are retained by this preset.
    #[must_use]
    pub const fn syscall_codes(&self) -> &'static [SyscallCode] {
        #[allow(clippy::enum_glob_use)]
        use SyscallCode::*;
        match self {
            RetainedEventsPreset::Bls12381Field => &[
                BLS12381_FP_ADD,
                BLS12381_FP_MUL,
                BLS12381_FP_SUB,
                BLS12381_ADD,
                BLS12381_DECOMPRESS,
                BLS12381_DOUBLE,
                BLS12381_FP2_ADD,
                BLS12381_FP2_SUB,
                BLS12381_FP2_MUL,
            ],
            RetainedEventsPreset::Bn254Field => &[
                BN254_FP_ADD,
                BN254_FP_MUL,
                BN254_FP_SUB,
                BN254_ADD,
                BN254_DOUBLE,
                BN254_FP2_ADD,
                BN254_FP2_SUB,
                BN254_FP2_MUL,
            ],
            RetainedEventsPreset::Sha256 => &[SHA_COMPRESS, SHA_EXTEND],
            RetainedEventsPreset::Poseidon2 => &[POSEIDON2],
            RetainedEventsPreset::U256Ops => &[UINT256_ADD_CARRY, UINT256_MUL_CARRY],
            RetainedEventsPreset::Secp256k1 => &[SECP256K1_ADD, SECP256K1_DOUBLE],
            RetainedEventsPreset::Keccak => &[KECCAK_PERMUTE],
        }
    }
}
