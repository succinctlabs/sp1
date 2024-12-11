use crate::{
    mode::Mode,
    request::{DEFAULT_CYCLE_LIMIT, DEFAULT_TIMEOUT},
};

pub struct ProofOpts {
    pub mode: Mode,
    pub timeout: u64,
    pub cycle_limit: u64,
}

impl Default for ProofOpts {
    fn default() -> Self {
        Self { mode: Mode::default(), timeout: DEFAULT_TIMEOUT, cycle_limit: DEFAULT_CYCLE_LIMIT }
    }
}
