pub mod tests {
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
}
