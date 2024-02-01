/// A system call is invoked by the the `ecall` instruction with a specific value in register t0.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum Syscall {
    /// Halts the program.
    HALT = 100,

    /// Loads a word supplied from the prover.
    LWA = 101,

    /// Executes the `SHA_EXTEND` precompile.
    SHA_EXTEND = 102,

    /// Executes the `SHA_COMPRESS` precompile.
    SHA_COMPRESS = 103,

    /// Executes the `ED_ADD` precompile.
    ED_ADD = 104,

    /// Executes the `ED_DECOMPRESS` precompile.
    ED_DECOMPRESS = 105,

    /// Executes the `KECCAK_PERMUTE` precompile.
    KECCAK_PERMUTE = 106,

    /// Executes the `SECP256K1_ADD` precompile.
    SECP256K1_ADD = 107,

    /// Executes the `SECP256K1_DOUBLE` precompile.
    SECP256K1_DOUBLE = 108,

    /// Executes the `K256_DECOMPRESS` precompile.
    SECP256K1_DECOMPRESS = 109,

    WRITE = 999,
}

impl Syscall {
    /// Create a syscall from a u32.
    pub fn from_u32(value: u32) -> Self {
        match value {
            100 => Syscall::HALT,
            101 => Syscall::LWA,
            102 => Syscall::SHA_EXTEND,
            103 => Syscall::SHA_COMPRESS,
            104 => Syscall::ED_ADD,
            105 => Syscall::ED_DECOMPRESS,
            106 => Syscall::KECCAK_PERMUTE,
            107 => Syscall::SECP256K1_ADD,
            108 => Syscall::SECP256K1_DOUBLE,
            109 => Syscall::SECP256K1_DECOMPRESS,
            999 => Syscall::WRITE,
            _ => panic!("invalid syscall number: {}", value),
        }
    }
}
