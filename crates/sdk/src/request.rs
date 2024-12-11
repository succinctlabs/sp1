use crate::mode::Mode;
use crate::opts::ProofOpts;
use crate::proof::SP1ProofWithPublicValues;
use crate::prover::Prover;
use anyhow::Result;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::SP1ProvingKey;
use std::future::{Future, IntoFuture};
use std::pin::Pin;

pub trait ProofRequest {
    fn run(
        self,
    ) -> Pin<Box<dyn Future<Output = Result<SP1ProofWithPublicValues>> + Send + 'static>>;
}

pub struct DynProofRequest<'a, 'b: 'a> {
    prover: &'a dyn Prover,
    elf: &'b [u8],
    pk: SP1ProvingKey,
    stdin: SP1Stdin,
    opts: ProofOpts,
}

impl<'a, 'b: 'a> DynProofRequest<'a, 'b> {
    pub fn new(
        prover: &'a dyn Prover,
        elf: &'b [u8],
        pk: SP1ProvingKey,
        stdin: SP1Stdin,
        opts: ProofOpts,
    ) -> Self {
        Self { prover, elf, pk, stdin, opts }
    }

    pub fn proof_type(mut self, mode: Mode) -> Self {
        self.opts.mode = mode;
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

    async fn run(self) -> Result<SP1ProofWithPublicValues> {
        self.prover.prove_with_options(&self.pk, &self.stdin, &self.opts).await
    }
}

impl<'a, 'b: 'a> IntoFuture for DynProofRequest<'a, 'b> {
    type Output = Result<SP1ProofWithPublicValues>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.run())
    }
}
