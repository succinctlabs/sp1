use crate::mode::Mode;
use crate::opts::ProofOpts;
use crate::proof::SP1ProofWithPublicValues;
use crate::prover::Prover;
use crate::provers::SP1VerificationError;
use crate::request::{ProofRequest, DEFAULT_TIMEOUT};
use crate::verify;

use anyhow::Result;
use async_trait::async_trait;

#[cfg(feature = "blocking")]
use futures::executor;

use sp1_core_executor::{ExecutionError, ExecutionReport, SP1Context};
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::io::SP1PublicValues;
use sp1_prover::components::DefaultProverComponents;
use sp1_prover::{SP1Prover, SP1ProvingKey, SP1VerifyingKey, SP1_CIRCUIT_VERSION};
use std::future::{Future, IntoFuture};
use std::pin::Pin;

pub struct LocalProver {
    pub prover: SP1Prover<DefaultProverComponents>,
}

impl LocalProver {
    pub fn new() -> Self {
        Self { prover: SP1Prover::new() }
    }

    pub fn builder() -> LocalProverBuilder {
        LocalProverBuilder::new()
    }
}

pub struct LocalProverBuilder {}

impl LocalProverBuilder {
    pub fn new() -> Self {
        Self {}
    }

    pub fn build(self) -> LocalProver {
        LocalProver::new()
    }
}

pub struct LocalProofRequest<'a> {
    pub prover: &'a LocalProver,
    pub pk: &'a SP1ProvingKey,
    pub stdin: &'a SP1Stdin,
    pub mode: Mode,
    pub timeout: u64,
}

impl<'a> LocalProofRequest<'a> {
    pub fn new(prover: &'a LocalProver, pk: &'a SP1ProvingKey, stdin: &'a SP1Stdin) -> Self {
        Self { prover, pk, stdin, timeout: DEFAULT_TIMEOUT, mode: Mode::default() }
    }

    pub fn with_mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }

    pub async fn run(self) -> Result<SP1ProofWithPublicValues> {
        self.prover
            .prove_with_options(
                self.pk,
                &self.stdin,
                &ProofOpts { timeout: self.timeout, mode: self.mode, cycle_limit: 0 },
            )
            .await
    }
}

#[async_trait]
impl Prover for LocalProver {
    async fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }

    async fn execute(
        &self,
        elf: &[u8],
        stdin: &SP1Stdin,
    ) -> Result<(SP1PublicValues, ExecutionReport), ExecutionError> {
        self.prover.execute(elf, stdin, SP1Context::default())
    }

    async fn prove_with_options(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        opts: &ProofOpts,
    ) -> Result<SP1ProofWithPublicValues> {
        let request = LocalProofRequest::new(self, pk, stdin).with_timeout(opts.timeout);
        request.run().await
    }

    #[cfg(feature = "blocking")]
    fn prove_with_options_sync(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        opts: &ProofOpts,
    ) -> Result<SP1ProofWithPublicValues> {
        let request = LocalProofRequest::new(self, pk, stdin).with_timeout(opts.timeout);
        executor::block_on(request.run())
    }

    async fn verify(
        &self,
        proof: &SP1ProofWithPublicValues,
        vk: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        verify::verify(&self.prover, SP1_CIRCUIT_VERSION, proof, vk)
    }
}

impl Default for LocalProver {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> IntoFuture for LocalProofRequest<'a> {
    type Output = Result<SP1ProofWithPublicValues>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.run())
    }
}
