#![warn(clippy::pedantic)]

//! This crate goal is to compile all programs in the `programs` folders to ELFs files,
//! and give an easy access to these ELFs from other crates, using the constants below.
//!
//! **Note:** If you added a new program, don't forget to add it to the workspace in the
//! `programs` folder to have if compiled to an ELF file.

use sp1_build::include_elf;

pub const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci-program-tests");

pub const FIBONACCI_BLAKE3_ELF: &[u8] = include_elf!("fibonacci-blake3-test");

pub const HELLO_WORLD_ELF: &[u8] = include_elf!("hello-world-program");

pub const ED25519_ELF: &[u8] = include_elf!("ed25519-program");

pub const CYCLE_TRACKER_ELF: &[u8] = include_elf!("cycle-tracker-test");

pub const ED_ADD_ELF: &[u8] = include_elf!("ed-add-test");

pub const ED_DECOMPRESS_ELF: &[u8] = include_elf!("ed-decompress-test");

pub const KECCAK_PERMUTE_ELF: &[u8] = include_elf!("keccak-permute-test");

pub const KECCAK256_ELF: &[u8] = include_elf!("keccak256-test");

pub const SECP256K1_ADD_ELF: &[u8] = include_elf!("secp256k1-add-test");

pub const SECP256K1_DECOMPRESS_ELF: &[u8] = include_elf!("secp256k1-decompress-test");

pub const SECP256K1_DOUBLE_ELF: &[u8] = include_elf!("secp256k1-double-test");

pub const SECP256R1_ADD_ELF: &[u8] = include_elf!("secp256r1-add-test");

pub const SECP256R1_DECOMPRESS_ELF: &[u8] = include_elf!("secp256r1-decompress-test");

pub const SECP256R1_DOUBLE_ELF: &[u8] = include_elf!("secp256r1-double-test");

pub const SHA_COMPRESS_ELF: &[u8] = include_elf!("sha-compress-test");

pub const SHA_EXTEND_ELF: &[u8] = include_elf!("sha-extend-test");

pub const SHA2_ELF: &[u8] = include_elf!("sha2-test");

pub const SSZ_WITHDRAWALS_ELF: &[u8] = include_elf!("ssz-withdrawals-test");

pub const BN254_ADD_ELF: &[u8] = include_elf!("bn254-add-test");

pub const BN254_DOUBLE_ELF: &[u8] = include_elf!("bn254-double-test");

pub const BN254_MUL_ELF: &[u8] = include_elf!("bn254-mul-test");

pub const SECP256K1_MUL_ELF: &[u8] = include_elf!("secp256k1-mul-test");

pub const BLS12381_ADD_ELF: &[u8] = include_elf!("bls12381-add-test");

pub const BLS12381_DOUBLE_ELF: &[u8] = include_elf!("bls12381-double-test");

pub const BLS12381_MUL_ELF: &[u8] = include_elf!("bls12381-mul-test");

pub const UINT256_MUL_ELF: &[u8] = include_elf!("biguint-mul-test");

pub const BLS12381_DECOMPRESS_ELF: &[u8] = include_elf!("bls-decompress-test");

pub const VERIFY_PROOF_ELF: &[u8] = include_elf!("verify-proof");

pub const PANIC_ELF: &[u8] = include_elf!("panic-test");

pub const BLS12381_FP_ELF: &[u8] = include_elf!("bls12381-fp-test");

pub const BLS12381_FP2_MUL_ELF: &[u8] = include_elf!("bls12381-fp2-mul-test");

pub const BLS12381_FP2_ADDSUB_ELF: &[u8] = include_elf!("bls12381-fp2-addsub-test");

pub const BN254_FP_ELF: &[u8] = include_elf!("bn254-fp-test");

pub const BN254_FP2_ADDSUB_ELF: &[u8] = include_elf!("bn254-fp2-addsub-test");

pub const BN254_FP2_MUL_ELF: &[u8] = include_elf!("bn254-fp2-mul-test");

pub const TENDERMINT_BENCHMARK_ELF: &[u8] = include_elf!("tendermint-benchmark-program");

pub const U256XU2048_MUL_ELF: &[u8] = include_elf!("u256x2048-mul");
