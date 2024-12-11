use crate::mode::Mode;

pub struct ProofOpts {
    pub mode: Mode,
    pub timeout: u64,
    pub cycle_limit: u64,
}

impl Default for ProofOpts {
    fn default() -> Self {
        // TODO better defaults
        Self { mode: Mode::default(), timeout: 10000, cycle_limit: 100000000 }
    }
}
