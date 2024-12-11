use crate::mode::Mode;

pub struct ProofOpts {
    pub mode: Mode,
    pub timeout: u64,
    pub cycle_limit: u64,
}
