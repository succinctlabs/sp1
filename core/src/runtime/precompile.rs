/// A precompile is an extensible piece of code that can be executed by the VM.
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
pub enum Precompile {
    /// Used to halt the program.
    HALT = 0,

    /// Used to read witness values from the prover.
    LWW = 1,

    /// Used to accelerate SHA256.
    SHA = 2,

    /// Used to accelerate bigint computations.
    BIGINT = 3,
}

impl Precompile {
    pub fn from_u32(n: u32) -> Self {
        match n {
            0 => Precompile::HALT,
            1 => Precompile::LWW,
            2 => Precompile::SHA,
            3 => Precompile::BIGINT,
            _ => panic!("unsupported precompile"),
        }
    }
}
