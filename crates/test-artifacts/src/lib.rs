#![warn(clippy::pedantic)]

//! This crate compiles all programs in the `programs` folder into ELF files
//! and provides easy access to these ELFs from other crates using the constants below.
//!
//! **Note:** If you add a new program, make sure to include it in the `programs` folder 
//! and the workspace configuration to have it compiled as an ELF file.

use sp1_build::include_elf;

// ===============================
// 🧮 Mathematical Operations
// ===============================

pub const UINT256_MUL_ELF: &[u8] = include_elf!("biguint-mul-test");
pub const U256XU2048_MUL_ELF: &[u8] = include_elf!("u256x2048-mul");
pub const CYCLE_TRACKER_ELF: &[u8] = include_elf!("cycle-tracker-test");
pub const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci-program-tests");

// ===============================
// 🔐 Cryptographic Algorithms
// ===============================

// Ed25519
pub const ED25519_ELF: &[u8] = include_elf!("ed25519-program");
pub const ED_ADD_ELF: &[u8] = include_elf!("ed-add-test");
pub const ED_DECOMPRESS_ELF: &[u8] = include_elf!("ed-decompress-test");

// Keccak (Ethereum hashing)
pub const KECCAK_PERMUTE_ELF: &[u8] = include_elf!("keccak-permute-test");
pub const KECCAK256_ELF: &[u8] = include_elf!("keccak256-test");

// SHA-2 (Secure Hash Algorithm)
pub const SHA2_ELF: &[u8] = include_elf!("sha2-test");
pub const SHA_COMPRESS_ELF: &[u8] = include_elf!("sha-compress-test");
pub const SHA_EXTEND_ELF: &[u8] = include_elf!("sha-extend-test");

// BN254 (Pairing-friendly curve)
pub const BN254_ADD_ELF: &[u8] = include_elf!("bn254-add-test");
pub const BN254_DOUBLE_ELF: &[u8] = include_elf!("bn254-double-test");
pub const BN254_MUL_ELF: &[u8] = include_elf!("bn254-mul-test");
pub const BN254_FP_ELF: &[u8] = include_elf!("bn254-fp-test");
pub const BN254_FP2_ADDSUB_ELF: &[u8] = include_elf!("bn254-fp2-addsub-test");
pub const BN254_FP2_MUL_ELF: &[u8] = include_elf!("bn254-fp2-mul-test");

// SECP256K1 (Bitcoin & Ethereum curve)
pub const SECP256K1_ADD_ELF: &[u8] = include_elf!("secp256k1-add-test");
pub const SECP256K1_DECOMPRESS_ELF: &[u8] = include_elf!("secp256k1-decompress-test");
pub const SECP256K1_DOUBLE_ELF: &[u8] = include_elf!("secp256k1-double-test");
pub const SECP256K1_MUL_ELF: &[u8] = include_elf!("secp256k1-mul-test");

// SECP256R1 (Standard elliptic curve)
pub const SECP256R1_ADD_ELF: &[u8] = include_elf!("secp256r1-add-test");
pub const SECP256R1_DECOMPRESS_ELF: &[u8] = include_elf!("secp256r1-decompress-test");
pub const SECP256R1_DOUBLE_ELF: &[u8] = include_elf!("secp256r1-double-test");

// BLS12-381 (ZK-SNARKs & Ethereum consensus)
pub const BLS12381_ADD_ELF: &[u8] = include_elf!("bls12381-add-test");
pub const BLS12381_DOUBLE_ELF: &[u8] = include_elf!("bls12381-double-test");
pub const BLS12381_MUL_ELF: &[u8] = include_elf!("bls12381-mul-test");
pub const BLS12381_FP_ELF: &[u8] = include_elf!("bls12381-fp-test");
pub const BLS12381_FP2_ADDSUB_ELF: &[u8] = include_elf!("bls12381-fp2-addsub-test");
pub const BLS12381_FP2_MUL_ELF: &[u8] = include_elf!("bls12381-fp2-mul-test");
pub const BLS12381_DECOMPRESS_ELF: &[u8] = include_elf!("bls-decompress-test");

// ===============================
// 🛠 Miscellaneous Tests & Proofs
// ===============================

pub const VERIFY_PROOF_ELF: &[u8] = include_elf!("verify-proof");
pub const SSZ_WITHDRAWALS_ELF: &[u8] = include_elf!("ssz-withdrawals-test");
pub const TENDERMINT_BENCHMARK_ELF: &[u8] = include_elf!("tendermint-benchmark-program");
pub const PANIC_ELF: &[u8] = include_elf!("panic-test");
