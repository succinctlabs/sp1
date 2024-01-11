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
}

impl Syscall {
    /// Create a syscall from a u32.
    pub fn from_u32(value: u32) -> Self {
        match value {
            100 => Syscall::HALT,
            101 => Syscall::LWA,
            102 => Syscall::SHA_EXTEND,
            _ => panic!("invalid syscall number: {}", value),
        }
    }
}
