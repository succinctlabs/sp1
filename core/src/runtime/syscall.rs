/// A system call is invoked by the the `ecall` instruction with a specific value in register t0.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Syscall {
    HALT = 0,
    LWA = 1,
}

impl Syscall {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => Syscall::HALT,
            1 => Syscall::LWA,
            _ => panic!("invalid syscall number: {}", value),
        }
    }
}
