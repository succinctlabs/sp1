#![warn(clippy::pedantic)]

use sp1_build::include_elf;
/// Compiled test programs. TODO elaborate.

pub const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci-program-tests");

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
