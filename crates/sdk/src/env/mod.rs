//! # SP1 Environment Prover
//!
//! A prover that can execute programs and generate proofs with a different implementation based on
//! the value of the `SP1_PROVER` environment variable.

use crate::{
    prover::{BaseProveRequest, SendFutureResult},
    CpuProver, LightProver, MockProver, Prover, SP1ProofWithPublicValues, SP1VerificationError,
    StatusCode,
};

#[cfg(feature = "cuda")]
use crate::{cuda::builder::CudaProverBuilder, CudaProver};
use sp1_core_executor::SP1CoreOpts;

#[cfg(feature = "network")]
use crate::NetworkProver;

pub mod pk;
/// The module that defines the prove request for the [`EnvProver`].
pub mod prove;
pub use pk::EnvProvingKey;
use prove::EnvProveRequest;
use sp1_core_machine::io::SP1Stdin;
use sp1_core_machine::riscv::RiscvAir;
use sp1_hypercube::Machine;
use sp1_primitives::{Elf, SP1Field};
use sp1_prover::{worker::SP1NodeCore, SP1VerifyingKey};

/// A prover that can execute programs and generate proofs with a different implementation based on
/// the value of the `SP1_PROVER` environment variable.
#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum EnvProver {
    /// A mock prover that does not prove anything.
    Mock(MockProver),
    /// A light prover that only executes and verifies but does not generate proofs.
    Light(LightProver),
    /// A CPU prover.
    Cpu(CpuProver),
    /// A CUDA prover.
    #[cfg(feature = "cuda")]
    Cuda(CudaProver),
    /// A network prover.
    #[cfg(feature = "network")]
    Network(NetworkProver),
}

impl EnvProver {
    /// Creates a new [`EnvProver`] from the environment.
    ///
    /// This method will read from the `SP1_PROVER` environment variable to determine which prover
    /// to use. If the variable is not set, it will default to the CPU prover.
    ///
    /// If the prover is a network prover, the `NETWORK_PRIVATE_KEY` variable must be set.
    pub async fn new() -> Self {
        Self::new_with_machine(RiscvAir::machine()).await
    }

    /// Same as [`Self::new`] but with a custom machine.
    pub async fn new_with_machine(machine: Machine<SP1Field, RiscvAir<SP1Field>>) -> Self {
        Self::from_env_with_opts_and_machine(None, machine).await
    }

    /// Updates the core options for this prover.
    ///
    /// This method allows you to configure the prover after creation.
    /// It recreates the prover with the new options based on the current environment settings.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_core_executor::SP1CoreOpts;
    /// use sp1_sdk::ProverClient;
    ///
    /// tokio_test::block_on(async {
    ///     let mut client = ProverClient::from_env().await;
    ///     let opts = SP1CoreOpts { shard_size: 500_000, ..Default::default() };
    ///     client = client.with_opts(opts).await;
    /// });
    /// ```
    pub async fn with_opts(self, opts: SP1CoreOpts) -> Self {
        Self::from_env_with_opts(Some(opts)).await
    }

    /// Creates an [`EnvProver`] from the environment with optional custom [`SP1CoreOpts`].
    ///
    /// This method will read from the `SP1_PROVER` environment variable to determine which prover
    /// to use. If the variable is not set, it will default to the CPU prover.
    ///
    /// If the prover is a network prover, the `NETWORK_PRIVATE_KEY` variable must be set.
    pub async fn from_env_with_opts(core_opts: Option<SP1CoreOpts>) -> Self {
        Self::from_env_with_opts_and_machine(core_opts, RiscvAir::machine()).await
    }

    /// Same as [`Self::from_env_with_opts`] but with a custom machine.
    pub async fn from_env_with_opts_and_machine(
        core_opts: Option<SP1CoreOpts>,
        machine: Machine<SP1Field, RiscvAir<SP1Field>>,
    ) -> Self {
        let prover = match std::env::var("SP1_PROVER") {
            Ok(prover) => prover,
            Err(_) => "cpu".to_string(),
        };

        match prover.as_str() {
            "cpu" => Self::Cpu(CpuProver::new_with_opts_and_machine(core_opts, machine).await),
            #[cfg(feature = "cuda")]
            "cuda" => Self::Cuda(CudaProverBuilder::new_with_machine(machine).build().await),
            #[cfg(not(feature = "cuda"))]
            "cuda" => panic!("The CUDA prover requires the `cuda` feature to be enabled"),
            "mock" => Self::Mock(MockProver::new_with_machine(machine).await),
            "light" => Self::Light(LightProver::new_with_machine(machine).await),
            #[cfg(feature = "network")]
            "network" => {
                let private_key =
                    std::env::var("NETWORK_PRIVATE_KEY").ok().filter(|k| !k.is_empty()).expect(
                        "NETWORK_PRIVATE_KEY environment variable is not set. \
                Please set it to your private key or use the .private_key() method.",
                    );

                let network_builder =
                    crate::network::builder::NetworkProverBuilder::new_with_machine(machine)
                        .private_key(&private_key);

                Self::Network(network_builder.build().await)
            }
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
            #[cfg(feature = "cuda")]
            Self::Cuda(prover) => prover.inner(),
            Self::Mock(prover) => prover.inner(),
            Self::Light(prover) => prover.inner(),
            #[cfg(feature = "network")]
            Self::Network(prover) => prover.inner(),
        }
    }
    fn setup(&self, elf: Elf) -> impl SendFutureResult<Self::ProvingKey, Self::Error> {
        async move {
            match self {
                Self::Cpu(prover) => {
                    let pk = prover.setup(elf).await?;
                    Ok(EnvProvingKey::cpu(pk))
                }
                #[cfg(feature = "cuda")]
                Self::Cuda(prover) => {
                    let pk = prover.setup(elf).await?;
                    Ok(EnvProvingKey::cuda(pk))
                }
                Self::Mock(prover) => {
                    let pk = prover.setup(elf).await?;
                    Ok(EnvProvingKey::mock(pk))
                }
                Self::Light(prover) => {
                    let pk = prover.setup(elf).await?;
                    Ok(EnvProvingKey::light(pk))
                }
                #[cfg(feature = "network")]
                Self::Network(prover) => {
                    let pk = prover.setup(elf).await?;
                    Ok(EnvProvingKey::network(pk))
                }
            }
        }
    }

    fn prove<'a>(&'a self, pk: &'a Self::ProvingKey, stdin: SP1Stdin) -> Self::ProveRequest<'a> {
        EnvProveRequest { base: BaseProveRequest::new(self, pk, stdin) }
    }

    fn verify(
        &self,
        proof: &SP1ProofWithPublicValues,
        vkey: &SP1VerifyingKey,
        status_code: Option<StatusCode>,
    ) -> Result<(), SP1VerificationError> {
        match self {
            Self::Cpu(prover) => prover.verify(proof, vkey, status_code),
            #[cfg(feature = "cuda")]
            Self::Cuda(prover) => prover.verify(proof, vkey, status_code),
            Self::Mock(prover) => prover.verify(proof, vkey, status_code),
            Self::Light(prover) => prover.verify(proof, vkey, status_code),
            #[cfg(feature = "network")]
            Self::Network(prover) => prover.verify(proof, vkey, status_code),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{prover::ProveRequest, utils::setup_logger, MockProver, Prover, SP1Stdin};

    use super::EnvProver;

    /// Regression: `EnvProver::Mock(...)` must delegate `verify` to the inner `MockProver`
    /// for Plonk and Groth16 proofs. Before the dispatch fix, the trait default routed mock
    /// proofs through the real verifier and failed parsing the formatted BN254 vkey hash
    /// string with `invalid digit found in string`.
    #[tokio::test]
    async fn test_envprover_mock_verifies_plonk_and_groth16() {
        setup_logger();
        let mock = MockProver::new().await;
        let pk =
            mock.setup(test_artifacts::FIBONACCI_ELF).await.expect("failed to setup proving key");

        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let plonk_proof =
            mock.prove(&pk, stdin).plonk().await.expect("failed to create mock Plonk proof");

        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let groth16_proof =
            mock.prove(&pk, stdin).groth16().await.expect("failed to create mock Groth16 proof");

        let env = EnvProver::Mock(mock);
        env.verify(&plonk_proof, &pk.vk, None)
            .expect("EnvProver::Mock must verify a mock Plonk proof");
        env.verify(&groth16_proof, &pk.vk, None)
            .expect("EnvProver::Mock must verify a mock Groth16 proof");
    }
}
