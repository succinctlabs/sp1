//! # SP1 Environment Prover
//!
//! A prover that can execute programs and generate proofs with a different implementation based on
//! the value of the `SP1_PROVER` environment variable.

use crate::blocking::{
    cuda::builder::CudaProverBuilder, prover::BaseProveRequest, CpuProver, CudaProver, LightProver,
    MockProver, Prover,
};
use sp1_core_executor::SP1CoreOpts;

pub mod pk;
/// The module that defines the prove request for the [`EnvProver`].
pub mod prove;
pub use pk::EnvProvingKey;
use prove::EnvProveRequest;
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::Elf;
use sp1_prover::worker::SP1NodeCore;

/// A prover that can execute programs and generate proofs with a different implementation based on
/// the value of the `SP1_PROVER` environment variable.
#[derive(Clone)]
pub enum EnvProver {
    /// A mock prover that does not prove anything.
    Mock(MockProver),
    /// A light prover that only executes and verifies but does not generate proofs.
    Light(LightProver),
    /// A CPU prover.
    Cpu(CpuProver),
    /// A CUDA prover.
    Cuda(CudaProver),
}

impl Default for EnvProver {
    fn default() -> Self {
        Self::from_env_with_opts(None)
    }
}

impl EnvProver {
    /// Creates a new [`EnvProver`] from the environment.
    ///
    /// This method will read from the `SP1_PROVER` environment variable to determine which prover
    /// to use. If the variable is not set, it will default to the CPU prover.
    ///
    /// If the prover is a network prover, the `NETWORK_PRIVATE_KEY` variable must be set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Updates the core options for this prover.
    ///
    /// This method allows you to configure the prover after creation.
    /// It recreates the prover with the new options based on the current environment settings.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_core_executor::SP1CoreOpts;
    /// use sp1_sdk::blocking::ProverClient;
    ///
    /// let mut client = ProverClient::from_env();
    /// let opts = SP1CoreOpts { shard_size: 500_000, ..Default::default() };
    /// client = client.with_opts(opts);
    /// ```
    #[must_use]
    pub fn with_opts(self, opts: SP1CoreOpts) -> Self {
        Self::from_env_with_opts(Some(opts))
    }

    /// Creates an [`EnvProver`] from the environment with optional custom [`SP1CoreOpts`].
    ///
    /// This method will read from the `SP1_PROVER` environment variable to determine which prover
    /// to use. If the variable is not set, it will default to the CPU prover.
    ///
    /// If the prover is a network prover, the `NETWORK_PRIVATE_KEY` variable must be set.
    #[must_use]
    pub fn from_env_with_opts(core_opts: Option<SP1CoreOpts>) -> Self {
        let prover = match std::env::var("SP1_PROVER") {
            Ok(prover) => prover,
            Err(_) => "cpu".to_string(),
        };

        match prover.as_str() {
            "cpu" => Self::Cpu(CpuProver::new_with_opts(core_opts)),
            "cuda" => Self::Cuda(CudaProverBuilder::default().build()),
            "mock" => Self::Mock(MockProver::new()),
            "light" => Self::Light(LightProver::new()),
            "network" => panic!("The network prover is not supported in the blocking client"),
            _ => unreachable!(),
        }
    }
}

impl Prover for EnvProver {
    type Error = anyhow::Error;
    type ProvingKey = EnvProvingKey;
    type ProveRequest<'a> = prove::EnvProveRequest<'a>;

    fn inner(&self) -> &SP1NodeCore {
        match self {
            Self::Cpu(prover) => prover.inner(),
            Self::Cuda(prover) => prover.inner(),
            Self::Mock(prover) => prover.inner(),
            Self::Light(prover) => prover.inner(),
        }
    }
    fn setup(&self, elf: Elf) -> Result<Self::ProvingKey, Self::Error> {
        match self {
            Self::Cpu(prover) => {
                let pk = prover.setup(elf)?;
                Ok(EnvProvingKey::cpu(pk))
            }
            Self::Cuda(prover) => {
                let pk = prover.setup(elf)?;
                Ok(EnvProvingKey::cuda(pk))
            }
            Self::Mock(prover) => {
                let pk = prover.setup(elf)?;
                Ok(EnvProvingKey::mock(pk))
            }
            Self::Light(prover) => {
                let pk = prover.setup(elf)?;
                Ok(EnvProvingKey::light(pk))
            }
        }
    }

    fn prove<'a>(&'a self, pk: &'a Self::ProvingKey, stdin: SP1Stdin) -> Self::ProveRequest<'a> {
        EnvProveRequest { base: BaseProveRequest::new(self, pk, stdin) }
    }
}
