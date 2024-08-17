//! RV32IM ELFs used for testing.

#[allow(dead_code)]
#[allow(missing_docs)]
pub mod tests {
    use crate::{Instruction, Opcode, Program};

    pub const CHESS_ELF: &[u8] =
        include_bytes!("../../../../examples/chess/program/elf/riscv32im-succinct-zkvm-elf");

    pub const FIBONACCI_IO_ELF: &[u8] =
        include_bytes!("../../../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");

    pub const IO_ELF: &[u8] =
        include_bytes!("../../../../examples/io/program/elf/riscv32im-succinct-zkvm-elf");

    pub const JSON_ELF: &[u8] =
        include_bytes!("../../../../examples/json/program/elf/riscv32im-succinct-zkvm-elf");

    pub const REGEX_ELF: &[u8] =
        include_bytes!("../../../../examples/regex/program/elf/riscv32im-succinct-zkvm-elf");

    pub const RSA_ELF: &[u8] =
        include_bytes!("../../../../examples/rsa/program/elf/riscv32im-succinct-zkvm-elf");

    pub const SSZ_WITHDRAWALS_ELF: &[u8] = include_bytes!(
        "../../../../examples/ssz-withdrawals/program/elf/riscv32im-succinct-zkvm-elf"
    );

    pub const TENDERMINT_ELF: &[u8] =
        include_bytes!("../../../../examples/tendermint/program/elf/riscv32im-succinct-zkvm-elf");

    pub const FIBONACCI_ELF: &[u8] =
        include_bytes!("../../../../tests/fibonacci/elf/riscv32im-succinct-zkvm-elf");

    pub const ED25519_ELF: &[u8] =
        include_bytes!("../../../../tests/ed25519/elf/riscv32im-succinct-zkvm-elf");

    pub const CYCLE_TRACKER_ELF: &[u8] =
        include_bytes!("../../../../tests/cycle-tracker/elf/riscv32im-succinct-zkvm-elf");

    pub const ED_ADD_ELF: &[u8] =
        include_bytes!("../../../../tests/ed-add/elf/riscv32im-succinct-zkvm-elf");

    pub const ED_DECOMPRESS_ELF: &[u8] =
        include_bytes!("../../../../tests/ed-decompress/elf/riscv32im-succinct-zkvm-elf");

    pub const KECCAK_PERMUTE_ELF: &[u8] =
        include_bytes!("../../../../tests/keccak-permute/elf/riscv32im-succinct-zkvm-elf");

    pub const KECCAK256_ELF: &[u8] =
        include_bytes!("../../../../tests/keccak256/elf/riscv32im-succinct-zkvm-elf");

    pub const SECP256K1_ADD_ELF: &[u8] =
        include_bytes!("../../../../tests/secp256k1-add/elf/riscv32im-succinct-zkvm-elf");

    pub const SECP256K1_DECOMPRESS_ELF: &[u8] =
        include_bytes!("../../../../tests/secp256k1-decompress/elf/riscv32im-succinct-zkvm-elf");

    pub const SECP256K1_DOUBLE_ELF: &[u8] =
        include_bytes!("../../../../tests/secp256k1-double/elf/riscv32im-succinct-zkvm-elf");

    pub const SHA_COMPRESS_ELF: &[u8] =
        include_bytes!("../../../../tests/sha-compress/elf/riscv32im-succinct-zkvm-elf");

    pub const SHA_EXTEND_ELF: &[u8] =
        include_bytes!("../../../../tests/sha-extend/elf/riscv32im-succinct-zkvm-elf");

    pub const SHA2_ELF: &[u8] =
        include_bytes!("../../../../tests/sha2/elf/riscv32im-succinct-zkvm-elf");

    pub const BN254_ADD_ELF: &[u8] =
        include_bytes!("../../../../tests/bn254-add/elf/riscv32im-succinct-zkvm-elf");

    pub const BN254_DOUBLE_ELF: &[u8] =
        include_bytes!("../../../../tests/bn254-double/elf/riscv32im-succinct-zkvm-elf");

    pub const BN254_MUL_ELF: &[u8] =
        include_bytes!("../../../../tests/bn254-mul/elf/riscv32im-succinct-zkvm-elf");

    pub const SECP256K1_MUL_ELF: &[u8] =
        include_bytes!("../../../../tests/secp256k1-mul/elf/riscv32im-succinct-zkvm-elf");

    pub const BLS12381_ADD_ELF: &[u8] =
        include_bytes!("../../../../tests/bls12381-add/elf/riscv32im-succinct-zkvm-elf");

    pub const BLS12381_DOUBLE_ELF: &[u8] =
        include_bytes!("../../../../tests/bls12381-double/elf/riscv32im-succinct-zkvm-elf");

    pub const BLS12381_MUL_ELF: &[u8] =
        include_bytes!("../../../../tests/bls12381-mul/elf/riscv32im-succinct-zkvm-elf");

    pub const UINT256_MUL_ELF: &[u8] =
        include_bytes!("../../../../tests/uint256-mul/elf/riscv32im-succinct-zkvm-elf");

    pub const BLS12381_DECOMPRESS_ELF: &[u8] =
        include_bytes!("../../../../tests/bls12381-decompress/elf/riscv32im-succinct-zkvm-elf");

    pub const VERIFY_PROOF_ELF: &[u8] =
        include_bytes!("../../../../tests/verify-proof/elf/riscv32im-succinct-zkvm-elf");

    pub const PANIC_ELF: &[u8] =
        include_bytes!("../../../../tests/panic/elf/riscv32im-succinct-zkvm-elf");

    pub const BLS12381_FP_ELF: &[u8] =
        include_bytes!("../../../../tests/bls12381-fp/elf/riscv32im-succinct-zkvm-elf");

    pub const BLS12381_FP2_MUL_ELF: &[u8] =
        include_bytes!("../../../../tests/bls12381-fp2-mul/elf/riscv32im-succinct-zkvm-elf");

    pub const BLS12381_FP2_ADDSUB_ELF: &[u8] =
        include_bytes!("../../../../tests/bls12381-fp2-addsub/elf/riscv32im-succinct-zkvm-elf");

    pub const BN254_FP_ELF: &[u8] =
        include_bytes!("../../../../tests/bn254-fp/elf/riscv32im-succinct-zkvm-elf");

    pub const BN254_FP2_ADDSUB_ELF: &[u8] =
        include_bytes!("../../../../tests/bn254-fp2-addsub/elf/riscv32im-succinct-zkvm-elf");

    pub const BN254_FP2_MUL_ELF: &[u8] =
        include_bytes!("../../../../tests/bn254-fp2-mul/elf/riscv32im-succinct-zkvm-elf");

    #[must_use]
    pub fn simple_program() -> Program {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
        ];
        Program::new(instructions, 0, 0)
    }

    /// Get the fibonacci program.
    ///
    /// # Panics
    ///
    /// This function will panic if the program fails to load.
    #[must_use]
    pub fn fibonacci_program() -> Program {
        Program::from(FIBONACCI_ELF).unwrap()
    }

    /// Get the SSZ withdrawals program.
    ///
    /// # Panics
    ///
    /// This function will panic if the program fails to load.
    #[must_use]
    pub fn ssz_withdrawals_program() -> Program {
        Program::from(KECCAK_PERMUTE_ELF).unwrap()
    }

    /// Get the panic program.
    ///
    /// # Panics
    ///
    /// This function will panic if the program fails to load.
    #[must_use]
    pub fn panic_program() -> Program {
        Program::from(PANIC_ELF).unwrap()
    }

    #[must_use]
    #[allow(clippy::unreadable_literal)]
    pub fn simple_memory_program() -> Program {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 0x12348765, false, true),
            // SW and LW
            Instruction::new(Opcode::SW, 29, 0, 0x27654320, false, true),
            Instruction::new(Opcode::LW, 28, 0, 0x27654320, false, true),
            // LBU
            Instruction::new(Opcode::LBU, 27, 0, 0x27654320, false, true),
            Instruction::new(Opcode::LBU, 26, 0, 0x27654321, false, true),
            Instruction::new(Opcode::LBU, 25, 0, 0x27654322, false, true),
            Instruction::new(Opcode::LBU, 24, 0, 0x27654323, false, true),
            // LB
            Instruction::new(Opcode::LB, 23, 0, 0x27654320, false, true),
            Instruction::new(Opcode::LB, 22, 0, 0x27654321, false, true),
            // LHU
            Instruction::new(Opcode::LHU, 21, 0, 0x27654320, false, true),
            Instruction::new(Opcode::LHU, 20, 0, 0x27654322, false, true),
            // LU
            Instruction::new(Opcode::LH, 19, 0, 0x27654320, false, true),
            Instruction::new(Opcode::LH, 18, 0, 0x27654322, false, true),
            // SB
            Instruction::new(Opcode::ADD, 17, 0, 0x38276525, false, true),
            // Save the value 0x12348765 into address 0x43627530
            Instruction::new(Opcode::SW, 29, 0, 0x43627530, false, true),
            Instruction::new(Opcode::SB, 17, 0, 0x43627530, false, true),
            Instruction::new(Opcode::LW, 16, 0, 0x43627530, false, true),
            Instruction::new(Opcode::SB, 17, 0, 0x43627531, false, true),
            Instruction::new(Opcode::LW, 15, 0, 0x43627530, false, true),
            Instruction::new(Opcode::SB, 17, 0, 0x43627532, false, true),
            Instruction::new(Opcode::LW, 14, 0, 0x43627530, false, true),
            Instruction::new(Opcode::SB, 17, 0, 0x43627533, false, true),
            Instruction::new(Opcode::LW, 13, 0, 0x43627530, false, true),
            // SH
            // Save the value 0x12348765 into address 0x43627530
            Instruction::new(Opcode::SW, 29, 0, 0x43627530, false, true),
            Instruction::new(Opcode::SH, 17, 0, 0x43627530, false, true),
            Instruction::new(Opcode::LW, 12, 0, 0x43627530, false, true),
            Instruction::new(Opcode::SH, 17, 0, 0x43627532, false, true),
            Instruction::new(Opcode::LW, 11, 0, 0x43627530, false, true),
        ];
        Program::new(instructions, 0, 0)
    }
}
