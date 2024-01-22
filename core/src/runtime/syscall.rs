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
            999 => Syscall::WRITE,
            _ => panic!("invalid syscall number: {}", value),
        }
    }
}
