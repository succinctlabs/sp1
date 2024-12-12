use crate::install::try_install_circuit_artifacts;
use crate::local::ProverType;
use crate::local::SP1VerificationError;
use crate::mode::Mode;
use crate::opts::ProofOpts;
use crate::proof::{SP1Proof, SP1ProofWithPublicValues};
use crate::prover::Prover;
use crate::request::DEFAULT_TIMEOUT;
use crate::verify;

use anyhow::Result;
use async_trait::async_trait;
use sp1_core_executor::{ExecutionError, ExecutionReport, SP1Context};
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::io::SP1PublicValues;
use sp1_prover::components::DefaultProverComponents;
use sp1_prover::{SP1Prover, SP1ProvingKey, SP1VerifyingKey, SP1_CIRCUIT_VERSION};
use sp1_stark::SP1ProverOpts;
use std::future::{Future, IntoFuture};
use std::pin::Pin;
use std::sync::Arc;
use tokio::task;

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

    fn id(&self) -> ProverType {
        ProverType::Mock
    }

    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }

    fn sp1_prover(&self) -> &SP1Prover {
        &self.prover
    }

    pub fn prove(&self, pk: Arc<SP1ProvingKey>, stdin: SP1Stdin) -> LocalProofRequest {
        LocalProofRequest::new(self, &pk, stdin)
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
    pub pk: &'a Arc<SP1ProvingKey>,
    pub stdin: SP1Stdin,
    pub mode: Mode,
    pub timeout: u64,
    pub version: String,
    pub sp1_prover_opts: SP1ProverOpts,
}

impl<'a> LocalProofRequest<'a> {
    pub fn new(prover: &'a LocalProver, pk: &'a Arc<SP1ProvingKey>, stdin: SP1Stdin) -> Self {
        Self {
            prover,
            pk,
            stdin,
            timeout: DEFAULT_TIMEOUT,
            mode: Mode::default(),
            version: SP1_CIRCUIT_VERSION.to_string(),
            sp1_prover_opts: SP1ProverOpts::default(),
        }
    }

    pub fn core(mut self) -> Self {
        self.mode = Mode::Core;
        self
    }

    pub fn compressed(mut self) -> Self {
        self.mode = Mode::Compressed;
        self
    }

    pub fn plonk(mut self) -> Self {
        self.mode = Mode::Plonk;
        self
    }

    pub fn groth16(mut self) -> Self {
        self.mode = Mode::Groth16;
        self
    }

    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_version(mut self, version: String) -> Self {
        self.version = version;
        self
    }

    pub fn with_sp1_prover_opts(mut self, opts: SP1ProverOpts) -> Self {
        self.sp1_prover_opts = opts;
        self
    }

    pub fn run(self) -> Result<SP1ProofWithPublicValues> {
        let context = SP1Context::default();
        Self::run_inner(
            &self.prover.prover,
            &**self.pk,
            self.stdin,
            self.mode,
            self.timeout,
            self.version,
            self.sp1_prover_opts,
        )
    }
}

impl LocalProver {
    fn run_inner(
        prover: &SP1Prover<DefaultProverComponents>,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        mode: Mode,
        timeout: u64,
        version: String,
        sp1_prover_opts: SP1ProverOpts,
    ) -> Result<SP1ProofWithPublicValues> {
        let context = SP1Context::default();

        // Generate the core proof
        let proof: sp1_prover::SP1ProofWithMetadata<sp1_prover::SP1CoreProofData> =
            prover.prove_core(&pk, &stdin, sp1_prover_opts.clone(), context)?;

        if mode == Mode::Core {
            return Ok(SP1ProofWithPublicValues {
                proof: SP1Proof::Core(proof.proof.0),
                stdin: proof.stdin,
                public_values: proof.public_values,
                sp1_version: version.to_string(),
            });
        }

        let deferred_proofs =
            stdin.proofs.iter().map(|(reduce_proof, _)| reduce_proof.clone()).collect();
        let public_values = proof.public_values.clone();

        // Generate the compressed proof
        let reduce_proof =
            prover.compress(&pk.vk, proof, deferred_proofs, sp1_prover_opts.clone())?;

        if mode == Mode::Compressed {
            return Ok(SP1ProofWithPublicValues {
                proof: SP1Proof::Compressed(Box::new(reduce_proof)),
                stdin,
                public_values,
                sp1_version: version,
            });
        }

        // Generate the shrink proof.
        let compress_proof = prover.shrink(reduce_proof, sp1_prover_opts)?;

        // Genenerate the wrap proof.
        let outer_proof = prover.wrap_bn254(compress_proof, sp1_prover_opts)?;

        if mode == Mode::Plonk {
            let plonk_bn254_artifacts = if sp1_prover::build::sp1_dev_mode() {
                sp1_prover::build::try_build_plonk_bn254_artifacts_dev(
                    &outer_proof.vk,
                    &outer_proof.proof,
                )
            } else {
                try_install_circuit_artifacts("plonk")
            };
            let proof = prover.wrap_plonk_bn254(outer_proof, &plonk_bn254_artifacts);

            return Ok(SP1ProofWithPublicValues {
                proof: SP1Proof::Plonk(proof),
                stdin,
                public_values,
                sp1_version: version.to_string(),
            });
        } else if mode == Mode::Groth16 {
            let groth16_bn254_artifacts = if sp1_prover::build::sp1_dev_mode() {
                sp1_prover::build::try_build_groth16_bn254_artifacts_dev(
                    &outer_proof.vk,
                    &outer_proof.proof,
                )
            } else {
                try_install_circuit_artifacts("groth16")
            };

            let proof = prover.wrap_groth16_bn254(outer_proof, &groth16_bn254_artifacts);
            return Ok(SP1ProofWithPublicValues {
                proof: SP1Proof::Groth16(proof),
                stdin,
                public_values,
                sp1_version: version.to_string(),
            });
        }

        unreachable!()
    }
}

#[async_trait]
impl Prover for LocalProver {
    async fn setup(&self, elf: Arc<[u8]>) -> Arc<SP1ProvingKey> {
        let prover = Arc::clone(&self.prover);
        let result = task::spawn_blocking(move || {
            let (pk, _vk) = prover.setup(&elf);
            Arc::new(pk)
        })
        .await
        .unwrap();

        result
    }

    #[cfg(feature = "blocking")]
    fn setup_sync(&self, elf: &[u8]) -> Arc<SP1ProvingKey> {
        let (pk, _vk) = self.prover.setup(elf);

        Arc::new(pk)
    }

    async fn execute(
        &self,
        elf: Arc<[u8]>,
        stdin: SP1Stdin,
    ) -> Result<(SP1PublicValues, ExecutionReport), ExecutionError> {
        let prover = Arc::clone(&self.prover);
        task::spawn_blocking(move || prover.execute(&elf, &stdin, SP1Context::default()))
            .await
            .unwrap()
    }

    #[cfg(feature = "blocking")]
    fn execute_sync(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
    ) -> Result<(SP1PublicValues, ExecutionReport), ExecutionError> {
        self.prover.execute(elf, &stdin, SP1Context::default())
    }

    async fn prove_with_options(
        &self,
        pk: Arc<SP1ProvingKey>,
        stdin: SP1Stdin,
        opts: ProofOpts,
    ) -> Result<SP1ProofWithPublicValues> {
        let mut req = self.prove(pk, stdin);

        if let Some(mode) = opts.mode {
            req.mode = mode;
        }

        if let Some(timeout) = opts.timeout {
            req.timeout = timeout;
        }

        if let Some(version) = opts.version {
            req.version = version;
        }

        if let Some(sp1_prover_opts) = opts.sp1_prover_opts {
            req.sp1_prover_opts = sp1_prover_opts;
        }

        req.await
    }

    #[cfg(feature = "blocking")]
    fn prove_with_options_sync(
        &self,
        pk: Arc<SP1ProvingKey>,
        stdin: SP1Stdin,
        opts: ProofOpts,
    ) -> Result<SP1ProofWithPublicValues> {
        let mut req = self.prove(pk, stdin);

        if let Some(mode) = opts.mode {
            req.mode = mode;
        }

        if let Some(timeout) = opts.timeout {
            req.timeout = timeout;
        }

        if let Some(version) = opts.version {
            req.version = version;
        }

        if let Some(sp1_prover_opts) = opts.sp1_prover_opts {
            req.sp1_prover_opts = sp1_prover_opts;
        }

        req.run()
    }

    async fn verify(
        &self,
        proof: Arc<SP1ProofWithPublicValues>,
        vk: Arc<SP1VerifyingKey>,
    ) -> Result<(), SP1VerificationError> {
        let prover = Arc::clone(&self.prover);

        task::spawn_blocking(move || verify::verify(&prover, SP1_CIRCUIT_VERSION, &proof, &vk))
            .await
            .unwrap()
    }

    #[cfg(feature = "blocking")]
    fn verify_sync(
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
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output>>>;

    fn into_future(self) -> Self::IntoFuture {
        let LocalProofRequest { prover, pk, stdin, mode, timeout, version, sp1_prover_opts } = self;

        let pk = Arc::clone(pk);
        let prover = prover.prover.clone();

        Box::pin(async move {
            task::spawn_blocking(move || {
                LocalProofRequest::run_inner(
                    &prover,
                    &**pk,
                    stdin,
                    mode,
                    timeout,
                    version,
                    sp1_prover_opts,
                )
            })
            .await
            .expect("To be able to join prove handle")
        })
    }
}
