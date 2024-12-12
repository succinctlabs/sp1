use crate::install::try_install_circuit_artifacts;
use crate::proof::{SP1Proof, SP1ProofWithPublicValues};
use crate::prover::Prover;
use crate::verify;
use crate::Mode;
use crate::ProofOpts;
use crate::SP1VerificationError;
use crate::{DEFAULT_CYCLE_LIMIT, DEFAULT_TIMEOUT};

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
/// An implementation of [crate::ProverClient] that can generate proofs locally.
pub struct LocalProver {
    prover: Arc<SP1Prover<DefaultProverComponents>>,
    timeout: u64,
    cycle_limit: u64,
}

impl Default for LocalProver {
    fn default() -> Self {
        LocalProver::new()
    }
}

impl LocalProver {
    /// Creates a new [`LocalProver`].
    ///
    /// Uses default timeout and cycle limit.
    pub fn new() -> Self {
        Self {
            prover: Arc::new(SP1Prover::new()),
            timeout: DEFAULT_TIMEOUT,
            cycle_limit: DEFAULT_CYCLE_LIMIT,
        }
    }

    /// Creates a new network prover builder. See [`LocalProverBuilder`] for more details.
    pub fn builder() -> LocalProverBuilder {
        LocalProverBuilder::new()
    }

    /// Get the underlying [`SP1Prover`].
    pub fn sp1_prover(&self) -> &SP1Prover {
        &self.prover
    }

    /// Create a new proof request. See [`LocalProofRequest`] for more details.
    pub fn prove<'a>(
        &'a self,
        pk: &'a Arc<SP1ProvingKey>,
        stdin: SP1Stdin,
    ) -> LocalProofRequest<'a> {
        LocalProofRequest::new(self, pk, stdin)
    }
}

pub struct LocalProverBuilder {
    timeout: Option<u64>,
    cycle_limit: Option<u64>,
}

impl Default for LocalProverBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalProverBuilder {
    /// Creates a new [`LocalProverBuilder`].
    pub fn new() -> Self {
        Self { timeout: None, cycle_limit: None }
    }

    /// Sets the timeout for proof requests.
    ///
    /// This is the maximum amount of time to wait for the request to be generated.
    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Sets the cycle limit for proof requests.
    ///
    /// This is the maximum number of cycles to allow for the execution of the request.
    pub fn with_cycle_limit(mut self, cycle_limit: u64) -> Self {
        self.cycle_limit = Some(cycle_limit);
        self
    }

    /// Builds the [`LocalProver`] with the given configuration.
    pub fn build(self) -> LocalProver {
        LocalProver {
            prover: Arc::new(SP1Prover::new()),
            timeout: self.timeout.unwrap_or(DEFAULT_TIMEOUT),
            cycle_limit: self.cycle_limit.unwrap_or(DEFAULT_CYCLE_LIMIT),
        }
    }
}

pub struct LocalProofRequest<'a> {
    prover: &'a LocalProver,
    pk: &'a Arc<SP1ProvingKey>,
    stdin: SP1Stdin,
    mode: Mode,
    version: String,
    timeout: u64,
    cycle_limit: u64,
    prover_ops: SP1ProverOpts,
}

impl<'a> LocalProofRequest<'a> {
    /// Creates a new [`LocalProofRequest`] using the prover's configuration and default values.
    pub fn new(prover: &'a LocalProver, pk: &'a Arc<SP1ProvingKey>, stdin: SP1Stdin) -> Self {
        Self {
            prover,
            pk,
            stdin,
            mode: Mode::default(),
            version: SP1_CIRCUIT_VERSION.to_string(),
            timeout: prover.timeout,
            cycle_limit: prover.cycle_limit,
            prover_ops: SP1ProverOpts::default(),
        }
    }

    fn mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
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

    pub fn version(mut self, version: String) -> Self {
        self.version = version;
        self
    }

    pub fn timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn cycle_limit(mut self, cycle_limit: u64) -> Self {
        self.cycle_limit = cycle_limit;
        self
    }

    pub fn prover_opts(mut self, opts: SP1ProverOpts) -> Self {
        self.prover_ops = opts;
        self
    }

    pub fn run(self) -> Result<SP1ProofWithPublicValues> {
        Self::run_inner(
            &self.prover.prover,
            self.pk,
            self.stdin,
            self.mode,
            self.timeout,
            self.cycle_limit,
            self.version,
            self.prover_ops,
        )
    }
}

impl<'a> LocalProofRequest<'a> {
    #[allow(clippy::too_many_arguments)
    fn run_inner(
        prover: &SP1Prover<DefaultProverComponents>,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        mode: Mode,
        _timeout: u64,
        cycle_limit: u64,
        version: String,
        prover_opts: SP1ProverOpts,
    ) -> Result<SP1ProofWithPublicValues> {
        // Set the max cycles on the context.
        let context = SP1Context::builder().max_cycles(cycle_limit).build();

        // Generate the core proof.
        let proof: sp1_prover::SP1ProofWithMetadata<sp1_prover::SP1CoreProofData> =
            prover.prove_core(pk, &stdin, prover_opts, context)?;

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

        // Generate the compressed proof.
        let reduce_proof = prover.compress(&pk.vk, proof, deferred_proofs, prover_opts)?;

        if mode == Mode::Compressed {
            return Ok(SP1ProofWithPublicValues {
                proof: SP1Proof::Compressed(Box::new(reduce_proof)),
                stdin,
                public_values,
                sp1_version: version,
            });
        }

        // Generate the shrink proof.
        let compress_proof = prover.shrink(reduce_proof, prover_opts)?;

        // Genenerate the wrap proof.
        let outer_proof = prover.wrap_bn254(compress_proof, prover_opts)?;

        if mode == Mode::Plonk {
            // Generate the Plonk proof.
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
            // Generate the Groth16 proof.
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

        task::spawn_blocking(move || {
            let (pk, _vk) = prover.setup(&elf);
            Arc::new(pk)
        })
        .await
        .unwrap()
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
        pk: &Arc<SP1ProvingKey>,
        stdin: SP1Stdin,
        opts: ProofOpts,
    ) -> Result<SP1ProofWithPublicValues> {
        self.prove(pk, stdin)
            .mode(opts.mode)
            .timeout(opts.timeout)
            .cycle_limit(opts.cycle_limit)
            .await
    }

    #[cfg(feature = "blocking")]
    fn prove_with_options_sync(
        &self,
        pk: &Arc<SP1ProvingKey>,
        stdin: SP1Stdin,
        opts: ProofOpts,
    ) -> Result<SP1ProofWithPublicValues> {
        self.prove(pk, stdin)
            .mode(opts.mode)
            .timeout(opts.timeout)
            .cycle_limit(opts.cycle_limit)
            .run()
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

impl<'a> IntoFuture for LocalProofRequest<'a> {
    type Output = Result<SP1ProofWithPublicValues>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        let LocalProofRequest {
            prover,
            pk,
            stdin,
            mode,
            timeout,
            cycle_limit,
            version,
            prover_ops: sp1_prover_opts,
        } = self;

        let pk = Arc::clone(pk);
        let prover = prover.prover.clone();

        Box::pin(async move {
            task::spawn_blocking(move || {
                LocalProofRequest::run_inner(
                    &prover,
                    &pk,
                    stdin,
                    mode,
                    timeout,
                    cycle_limit,
                    version,
                    sp1_prover_opts,
                )
            })
            .await
            .expect("To be able to join prove handle")
        })
    }
}

pub struct LocalProverBuilder {
    timeout: Option<u64>,
    cycle_limit: Option<u64>,
}

impl Default for LocalProverBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalProverBuilder {
    /// Creates a new [`LocalProverBuilder`].
    pub fn new() -> Self {
        Self { timeout: None, cycle_limit: None }
    }

    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn with_cycle_limit(mut self, cycle_limit: u64) -> Self {
        self.cycle_limit = Some(cycle_limit);
        self
    }

    pub fn build(self) -> LocalProver {
        LocalProver {
            prover: Arc::new(SP1Prover::new()),
            timeout: self.timeout.unwrap_or(DEFAULT_TIMEOUT),
            cycle_limit: self.cycle_limit.unwrap_or(DEFAULT_CYCLE_LIMIT),
        }
    }
}
