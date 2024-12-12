use crate::mode::Mode;
use crate::opts::ProofOpts;
use crate::proof::SP1ProofWithPublicValues;
use crate::prover::Prover;
use anyhow::Result;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::SP1ProvingKey;
use std::future::{Future, IntoFuture};
use std::pin::Pin;
use std::sync::Arc;

/// The default timeout seconds for a proof request to be generated (4 hours).
pub const DEFAULT_TIMEOUT: u64 = 14400;

/// The default cycle limit for a proof request.
pub const DEFAULT_CYCLE_LIMIT: u64 = 100_000_000;

pub struct DynProofRequest<'a> {
    prover: &'a dyn Prover,
    pk: Arc<SP1ProvingKey>,
    stdin: SP1Stdin,
    opts: ProofOpts,
}

impl<'a> DynProofRequest<'a> {
    pub fn new(
        prover: &'a dyn Prover,
        pk: Arc<SP1ProvingKey>,
        stdin: SP1Stdin,
        opts: ProofOpts,
    ) -> Self {
        Self { prover, pk, stdin, opts }
    }

    pub fn core(mut self) -> Self {
        self.opts.mode = Mode::Core;
        self
    }

    pub fn compressed(mut self) -> Self {
        self.opts.mode = Mode::Compressed;
        self
    }

    pub fn plonk(mut self) -> Self {
        self.opts.mode = Mode::Plonk;
        self
    }

    pub fn groth16(mut self) -> Self {
        self.opts.mode = Mode::Groth16;
        self
    }

    pub fn timeout(mut self, timeout: u64) -> Self {
        self.opts.timeout = timeout;
        self
    }

    pub fn cycle_limit(mut self, cycle_limit: u64) -> Self {
        self.opts.cycle_limit = cycle_limit;
        self
    }

    #[cfg(feature = "blocking")]
    fn run(self) -> Result<SP1ProofWithPublicValues> {
        self.prover.prove_with_options_sync(&self.pk, self.stdin, self.opts)
    }
}

impl<'a> IntoFuture for DynProofRequest<'a> {
    type Output = Result<SP1ProofWithPublicValues>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        self.prover.prove_with_options(self.pk, self.stdin, self.opts)
    }
}
