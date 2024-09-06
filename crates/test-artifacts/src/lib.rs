#![warn(clippy::pedantic)]
/// Compiled test programs. TODO elaborate.

pub const FIBONACCI_ELF: &[u8] =
    include_bytes!("../programs/fibonacci/elf/riscv32im-succinct-zkvm-elf");

pub const ED25519_ELF: &[u8] =
    include_bytes!("../programs/ed25519/elf/riscv32im-succinct-zkvm-elf");

pub const CYCLE_TRACKER_ELF: &[u8] =
    include_bytes!("../programs/cycle-tracker/elf/riscv32im-succinct-zkvm-elf");

pub const ED_ADD_ELF: &[u8] = include_bytes!("../programs/ed-add/elf/riscv32im-succinct-zkvm-elf");

pub const ED_DECOMPRESS_ELF: &[u8] =
    include_bytes!("../programs/ed-decompress/elf/riscv32im-succinct-zkvm-elf");

pub const KECCAK_PERMUTE_ELF: &[u8] =
    include_bytes!("../programs/keccak-permute/elf/riscv32im-succinct-zkvm-elf");

pub const KECCAK256_ELF: &[u8] =
    include_bytes!("../programs/keccak256/elf/riscv32im-succinct-zkvm-elf");

pub const SECP256K1_ADD_ELF: &[u8] =
    include_bytes!("../programs/secp256k1-add/elf/riscv32im-succinct-zkvm-elf");

pub const SECP256K1_DECOMPRESS_ELF: &[u8] =
    include_bytes!("../programs/secp256k1-decompress/elf/riscv32im-succinct-zkvm-elf");

pub const SECP256K1_DOUBLE_ELF: &[u8] =
    include_bytes!("../programs/secp256k1-double/elf/riscv32im-succinct-zkvm-elf");

pub const SHA_COMPRESS_ELF: &[u8] =
    include_bytes!("../programs/sha-compress/elf/riscv32im-succinct-zkvm-elf");

pub const SHA_EXTEND_ELF: &[u8] =
    include_bytes!("../programs/sha-extend/elf/riscv32im-succinct-zkvm-elf");

pub const SHA2_ELF: &[u8] = include_bytes!("../programs/sha2/elf/riscv32im-succinct-zkvm-elf");

pub const BN254_ADD_ELF: &[u8] =
    include_bytes!("../programs/bn254-add/elf/riscv32im-succinct-zkvm-elf");

pub const BN254_DOUBLE_ELF: &[u8] =
    include_bytes!("../programs/bn254-double/elf/riscv32im-succinct-zkvm-elf");

pub const BN254_MUL_ELF: &[u8] =
    include_bytes!("../programs/bn254-mul/elf/riscv32im-succinct-zkvm-elf");

pub const SECP256K1_MUL_ELF: &[u8] =
    include_bytes!("../programs/secp256k1-mul/elf/riscv32im-succinct-zkvm-elf");

pub const BLS12381_ADD_ELF: &[u8] =
    include_bytes!("../programs/bls12381-add/elf/riscv32im-succinct-zkvm-elf");

pub const BLS12381_DOUBLE_ELF: &[u8] =
    include_bytes!("../programs/bls12381-double/elf/riscv32im-succinct-zkvm-elf");

pub const BLS12381_MUL_ELF: &[u8] =
    include_bytes!("../programs/bls12381-mul/elf/riscv32im-succinct-zkvm-elf");

pub const UINT256_MUL_ELF: &[u8] =
    include_bytes!("../programs/uint256-mul/elf/riscv32im-succinct-zkvm-elf");

pub const BLS12381_DECOMPRESS_ELF: &[u8] =
    include_bytes!("../programs/bls12381-decompress/elf/riscv32im-succinct-zkvm-elf");

pub const VERIFY_PROOF_ELF: &[u8] =
    include_bytes!("../programs/verify-proof/elf/riscv32im-succinct-zkvm-elf");

pub const PANIC_ELF: &[u8] = include_bytes!("../programs/panic/elf/riscv32im-succinct-zkvm-elf");

pub const BLS12381_FP_ELF: &[u8] =
    include_bytes!("../programs/bls12381-fp/elf/riscv32im-succinct-zkvm-elf");

pub const BLS12381_FP2_MUL_ELF: &[u8] =
    include_bytes!("../programs/bls12381-fp2-mul/elf/riscv32im-succinct-zkvm-elf");

pub const BLS12381_FP2_ADDSUB_ELF: &[u8] =
    include_bytes!("../programs/bls12381-fp2-addsub/elf/riscv32im-succinct-zkvm-elf");

pub const BN254_FP_ELF: &[u8] =
    include_bytes!("../programs/bn254-fp/elf/riscv32im-succinct-zkvm-elf");

pub const BN254_FP2_ADDSUB_ELF: &[u8] =
    include_bytes!("../programs/bn254-fp2-addsub/elf/riscv32im-succinct-zkvm-elf");

pub const BN254_FP2_MUL_ELF: &[u8] =
    include_bytes!("../programs/bn254-fp2-mul/elf/riscv32im-succinct-zkvm-elf");
