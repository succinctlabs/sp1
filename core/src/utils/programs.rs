pub mod tests {
    /// Demos.

    pub const CHESS_ELF: &[u8] =
        include_bytes!("../../../examples/chess/program/elf/riscv32im-succinct-zkvm-elf");

    pub const FIBONACCI_IO_ELF: &[u8] =
        include_bytes!("../../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");

    pub const IO_ELF: &[u8] =
        include_bytes!("../../../examples/io/program/elf/riscv32im-succinct-zkvm-elf");

    pub const JSON_ELF: &[u8] =
        include_bytes!("../../../examples/json/program/elf/riscv32im-succinct-zkvm-elf");

    pub const REGEX_ELF: &[u8] =
        include_bytes!("../../../examples/regex/program/elf/riscv32im-succinct-zkvm-elf");

    pub const RSA_ELF: &[u8] =
        include_bytes!("../../../examples/rsa/program/elf/riscv32im-succinct-zkvm-elf");

    pub const SSZ_WITHDRAWALS_ELF: &[u8] =
        include_bytes!("../../../examples/ssz-withdrawals/program/elf/riscv32im-succinct-zkvm-elf");

    pub const TENDERMINT_ELF: &[u8] =
        include_bytes!("../../../examples/tendermint/program/elf/riscv32im-succinct-zkvm-elf");

    /// Tests.

    pub const FIBONACCI_ELF: &[u8] =
        include_bytes!("../../../tests/fibonacci/elf/riscv32im-succinct-zkvm-elf");

    pub const ED25519_ELF: &[u8] =
        include_bytes!("../../../tests/ed25519/elf/riscv32im-succinct-zkvm-elf");

    pub const CYCLE_TRACKER_ELF: &[u8] =
        include_bytes!("../../../tests/cycle-tracker/elf/riscv32im-succinct-zkvm-elf");

    pub const ECRECOVER_ELF: &[u8] =
        include_bytes!("../../../tests/ecrecover/elf/riscv32im-succinct-zkvm-elf");

    pub const ED_ADD_ELF: &[u8] =
        include_bytes!("../../../tests/ed-add/elf/riscv32im-succinct-zkvm-elf");

    pub const ED_DECOMPRESS_ELF: &[u8] =
        include_bytes!("../../../tests/ed-decompress/elf/riscv32im-succinct-zkvm-elf");

    pub const KECCAK_PERMUTE_ELF: &[u8] =
        include_bytes!("../../../tests/keccak-permute/elf/riscv32im-succinct-zkvm-elf");

    pub const KECCAK256_ELF: &[u8] =
        include_bytes!("../../../tests/keccak256/elf/riscv32im-succinct-zkvm-elf");

    pub const SECP256K1_ADD_ELF: &[u8] =
        include_bytes!("../../../tests/secp256k1-add/elf/riscv32im-succinct-zkvm-elf");

    pub const SECP256K1_DECOMPRESS_ELF: &[u8] =
        include_bytes!("../../../tests/secp256k1-decompress/elf/riscv32im-succinct-zkvm-elf");

    pub const SECP256K1_DOUBLE_ELF: &[u8] =
        include_bytes!("../../../tests/secp256k1-double/elf/riscv32im-succinct-zkvm-elf");

    pub const SHA_COMPRESS_ELF: &[u8] =
        include_bytes!("../../../tests/sha-compress/elf/riscv32im-succinct-zkvm-elf");

    pub const SHA_EXTEND_ELF: &[u8] =
        include_bytes!("../../../tests/sha-extend/elf/riscv32im-succinct-zkvm-elf");

    pub const SHA2_ELF: &[u8] =
        include_bytes!("../../../tests/sha2/elf/riscv32im-succinct-zkvm-elf");

    pub const BN254_ADD_ELF: &[u8] =
        include_bytes!("../../../tests/bn254-add/elf/riscv32im-succinct-zkvm-elf");

    pub const BN254_DOUBLE_ELF: &[u8] =
        include_bytes!("../../../tests/bn254-double/elf/riscv32im-succinct-zkvm-elf");

    pub const BN254_MUL_ELF: &[u8] =
        include_bytes!("../../../tests/bn254-mul/elf/riscv32im-succinct-zkvm-elf");

    pub const SECP256K1_MUL_ELF: &[u8] =
        include_bytes!("../../../tests/secp256k1-mul/elf/riscv32im-succinct-zkvm-elf");

    pub const BLS12381_ADD_ELF: &[u8] =
        include_bytes!("../../../tests/bls12381-add/elf/riscv32im-succinct-zkvm-elf");

    pub const BLS12381_DOUBLE_ELF: &[u8] =
        include_bytes!("../../../tests/bls12381-double/elf/riscv32im-succinct-zkvm-elf");

    pub const BLS12381_MUL_ELF: &[u8] =
        include_bytes!("../../../tests/bls12381-mul/elf/riscv32im-succinct-zkvm-elf");

    pub const UINT256_MUL_ELF: &[u8] =
        include_bytes!("../../../tests/uint256-mul/elf/riscv32im-succinct-zkvm-elf");

    pub const FP_MUL_ELF: &[u8] =
        include_bytes!("../../../tests/fp-mul/elf/riscv32im-succinct-zkvm-elf");

    pub const FP12_MUL_ELF: &[u8] =
        include_bytes!("../../../tests/fp12-mul/elf/riscv32im-succinct-zkvm-elf");

    pub const BLS12381_DECOMPRESS_ELF: &[u8] =
        include_bytes!("../../../tests/bls12381-decompress/elf/riscv32im-succinct-zkvm-elf");

    pub const VERIFY_PROOF_ELF: &[u8] =
        include_bytes!("../../../tests/verify-proof/elf/riscv32im-succinct-zkvm-elf");

    pub const PANIC_ELF: &[u8] =
        include_bytes!("../../../tests/panic/elf/riscv32im-succinct-zkvm-elf");
}
