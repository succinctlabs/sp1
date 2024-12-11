use crate::mode::Mode;
use crate::opts::ProofOpts;
use crate::proof::{SP1Proof, SP1ProofKind, SP1ProofWithPublicValues};
use crate::prover::Prover;
use crate::provers::SP1VerificationError;
use crate::request::DEFAULT_TIMEOUT;
use crate::verify;

use anyhow::Result;
use async_trait::async_trait;

use tokio::task;

use sp1_core_executor::{ExecutionError, ExecutionReport, SP1Context};
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::io::SP1PublicValues;
use sp1_prover::components::DefaultProverComponents;
use sp1_prover::{SP1Prover, SP1ProvingKey, SP1VerifyingKey, SP1_CIRCUIT_VERSION};
use std::future::{Future, IntoFuture};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct LocalProver {
    prover: Arc<SP1Prover<DefaultProverComponents>>,
}

impl LocalProver {
    pub fn new() -> Self {
        Self { prover: Arc::new(SP1Prover::new()) }
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
    pub stdin: SP1Stdin,
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

    fn run_inner(
        prover: Arc<SP1Prover<DefaultProverComponents>>,
        pk: SP1ProvingKey,
        stdin: SP1Stdin,
        mode: Mode,
        timeout: u64,
    ) -> Result<SP1ProofWithPublicValues> {
        // Generate the core proof.
        let proof: sp1_prover::SP1ProofWithMetadata<sp1_prover::SP1CoreProofData> = self
            .prover
            .prove_core(self.pk, &self.stdin, self.opts.sp1_prover_opts, self.context)?;
        if kind == SP1ProofKind::Core {
            return Ok(SP1ProofWithPublicValues {
                proof: SP1Proof::Core(proof.proof.0),
                stdin: proof.stdin,
                public_values: proof.public_values,
                sp1_version: self.version().to_string(),
            });
        }

        let deferred_proofs =
            self.stdin.proofs.iter().map(|(reduce_proof, _)| reduce_proof.clone()).collect();
        let public_values = proof.public_values.clone();

        // Generate the compressed proof.
        let reduce_proof =
            self.prover.compress(&pk.vk, proof, deferred_proofs, opts.sp1_prover_opts)?;
        if kind == SP1ProofKind::Compressed {
            return Ok(SP1ProofWithPublicValues {
                proof: SP1Proof::Compressed(Box::new(reduce_proof)),
                stdin,
                public_values,
                sp1_version: self.version().to_string(),
            });
        }

        // Generate the shrink proof.
        let compress_proof = self.prover.shrink(reduce_proof, opts.sp1_prover_opts)?;

        // Genenerate the wrap proof.
        let outer_proof = self.prover.wrap_bn254(compress_proof, opts.sp1_prover_opts)?;

        if kind == SP1ProofKind::Plonk {
            let plonk_bn254_artifacts = if sp1_prover::build::sp1_dev_mode() {
                sp1_prover::build::try_build_plonk_bn254_artifacts_dev(
                    &outer_proof.vk,
                    &outer_proof.proof,
                )
            } else {
                try_install_circuit_artifacts("plonk")
            };
            let proof = self.prover.wrap_plonk_bn254(outer_proof, &plonk_bn254_artifacts);

            return Ok(SP1ProofWithPublicValues {
                proof: SP1Proof::Plonk(proof),
                stdin,
                public_values,
                sp1_version: self.version().to_string(),
            });
        } else if kind == SP1ProofKind::Groth16 {
            let groth16_bn254_artifacts = if sp1_prover::build::sp1_dev_mode() {
                sp1_prover::build::try_build_groth16_bn254_artifacts_dev(
                    &outer_proof.vk,
                    &outer_proof.proof,
                )
            } else {
                try_install_circuit_artifacts("groth16")
            };

            let proof = self.prover.wrap_groth16_bn254(outer_proof, &groth16_bn254_artifacts);
            return Ok(SP1ProofWithPublicValues {
                proof: SP1Proof::Groth16(proof),
                stdin,
                public_values,
                sp1_version: self.version().to_string(),
            });
        }

        unreachable!()
    }

    pub fn run(self) -> Result<SP1ProofWithPublicValues> {
        self.run_inner(self.prover, self.pk, self.stdin, self.mode, self.timeout)
    }
}

#[async_trait]
impl Prover for LocalProver {
    async fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        let elf = elf.to_vec();
        let prover = Arc::clone(&self.prover);
        task::spawn_blocking(move || prover.setup(&elf)).await.unwrap()
    }

    #[cfg(feature = "blocking")]
    fn setup_sync(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }

    async fn execute(
        &self,
        elf: &[u8],
        stdin: &SP1Stdin,
    ) -> Result<(SP1PublicValues, ExecutionReport), ExecutionError> {
        let elf = elf.to_vec();
        let prover = Arc::clone(&self.prover);
        task::spawn_blocking(move || prover.execute(&elf, stdin, SP1Context::default()))
            .await
            .unwrap()
    }

    #[cfg(feature = "blocking")]
    fn execute_sync(
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
        task::spawn_blocking(move || request.run()).await.unwrap()
    }

    #[cfg(feature = "blocking")]
    fn prove_with_options_sync(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        opts: &ProofOpts,
    ) -> Result<SP1ProofWithPublicValues> {
        let request = LocalProofRequest::new(self, pk, stdin).with_timeout(opts.timeout);
        request.run()
    }

    async fn verify(
        &self,
        proof: &SP1ProofWithPublicValues,
        vk: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        task::spawn_blocking(move || verify::verify(&self.prover, SP1_CIRCUIT_VERSION, proof, vk))
            .await
            .unwrap()
    }

    #[cfg(feature = "blocking")]
    fn verify_sync(
        &self,
        proof: &SP1ProofWithPublicValues,
        vk: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        let vk = vk.clone();
        let proof = proof.clone();
        let prover = Arc::clone(&self.prover);
        task::spawn_blocking(move || verify::verify(&prover, SP1_CIRCUIT_VERSION, &proof, &vk))
            .await
            .unwrap()
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
        Box::pin(async move { self.run() })
    }
}
