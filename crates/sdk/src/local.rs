use crate::mode::Mode;
use crate::prover::Prover;
use crate::request::ProofRequest;

use anyhow::Result;
use async_trait::async_trait;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::SP1ProvingKey;
use std::future::{Future, IntoFuture};
use std::pin::Pin;
use std::time::Duration;

use crate::{CpuProver, SP1ProofWithPublicValues};

pub struct LocalProver {
    cpu_prover: CpuProver,
}

impl LocalProver {
    pub fn new() -> Self {
        Self { cpu_prover: CpuProver::new() }
    }

    pub fn cpu_prover(&self) -> &CpuProver {
        &self.cpu_prover
    }

    pub fn prove_with_options(
        &self,
        request: LocalProofRequest,
    ) -> Result<SP1ProofWithPublicValues> {
        self.cpu_prover.prove(request.pk, request.stdin)
    }
}

impl<'a> LocalProofRequest<'a> {
    pub fn new(prover: &'a LocalProver, pk: &'a SP1ProvingKey, stdin: SP1Stdin) -> Self {
        Self { prover, pk, stdin, timeout: None, mode: Mode::default() }
    }

    pub fn with_mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub async fn run(self) -> Result<SP1ProofWithPublicValues> {
        self.prover.prove_with_options(self)
    }
}

#[async_trait]
impl Prover for LocalProver {
    fn cpu_prover(&self) -> &CpuProver {
        self.cpu_prover()
    }

    async fn prove(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1ProofWithPublicValues> {
        LocalProofRequest::new(self, pk, stdin).await
    }
}

impl Default for LocalProver {
    fn default() -> Self {
        Self::new()
    }
}
// impl ProofRequest for LocalProofRequest<'_> {
//     async fn run(self) -> Result<SP1ProofWithPublicValues> {
//         self.prover.prove_with_options(self)
//     }
// }

pub struct LocalProofRequest<'a> {
    pub prover: &'a LocalProver,
    pub pk: &'a SP1ProvingKey,
    pub stdin: SP1Stdin,
    pub mode: Mode,
    pub timeout: Option<Duration>,
}

impl<'a> LocalProofRequest<'a> {
    pub fn new(prover: &'a LocalProver, pk: &'a SP1ProvingKey, stdin: SP1Stdin) -> Self {
        Self { prover, pk, stdin, timeout: None, mode: Mode::default() }
    }

    pub fn with_mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub async fn run(self) -> Result<SP1ProofWithPublicValues> {
        self.prover.prove_with_options(self)
    }
}

impl<'a> ProofRequest for LocalProofRequest<'a> {
    fn run(
        self,
    ) -> Pin<Box<dyn Future<Output = Result<SP1ProofWithPublicValues>> + Send + 'static>> {
        Box::pin(async move { self.prover.prove_with_options(self) })
    }
}

impl<'a> IntoFuture for LocalProofRequest<'a> {
    type Output = Result<SP1ProofWithPublicValues>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            tokio::task::spawn_blocking(move || self.run()).await.map_err(|e| anyhow::anyhow!(e))?
        })
    }
}
