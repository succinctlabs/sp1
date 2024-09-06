#[cfg(test)]
pub mod tests {
    use sp1_core_executor::Program;

    /// Demos.

    pub const CHESS_ELF: &[u8] =
        include_bytes!("../../../../../examples/chess/program/elf/riscv32im-succinct-zkvm-elf");

    pub const FIBONACCI_IO_ELF: &[u8] =
        include_bytes!("../../../../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");

    pub const IO_ELF: &[u8] =
        include_bytes!("../../../../../examples/io/program/elf/riscv32im-succinct-zkvm-elf");

    pub const JSON_ELF: &[u8] =
        include_bytes!("../../../../../examples/json/program/elf/riscv32im-succinct-zkvm-elf");

    pub const REGEX_ELF: &[u8] =
        include_bytes!("../../../../../examples/regex/program/elf/riscv32im-succinct-zkvm-elf");

    pub const RSA_ELF: &[u8] =
        include_bytes!("../../../../../examples/rsa/program/elf/riscv32im-succinct-zkvm-elf");

    pub const SSZ_WITHDRAWALS_ELF: &[u8] = include_bytes!(
        "../../../../../examples/ssz-withdrawals/program/elf/riscv32im-succinct-zkvm-elf"
    );

    pub const TENDERMINT_ELF: &[u8] = include_bytes!(
        "../../../../../examples/tendermint/program/elf/riscv32im-succinct-zkvm-elf"
    );

    /// Tests.
    pub use test_artifacts::*;

    /// Get the fibonacci program.
    ///
    /// # Panics
    ///
    /// This function will panic if the program fails to load.
    #[cfg(test)]
    #[must_use]
    pub fn fibonacci_program() -> Program {
        Program::from(FIBONACCI_ELF).unwrap()
    }

    /// Get the SSZ withdrawals program.
    ///
    /// # Panics
    ///
    /// This function will panic if the program fails to load.
    #[cfg(test)]
    #[must_use]
    pub fn ssz_withdrawals_program() -> Program {
        Program::from(KECCAK_PERMUTE_ELF).unwrap()
    }

    /// Get the panic program.
    ///
    /// # Panics
    ///
    /// This function will panic if the program fails to load.
    #[cfg(test)]
    #[must_use]
    pub fn panic_program() -> Program {
        Program::from(PANIC_ELF).unwrap()
    }
}
