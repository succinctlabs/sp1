use super::{IntoSendFutureResult, Prover};
use crate::{ProvingKey, SP1ProofMode, SP1ProofWithPublicValues, StatusCode};
use sp1_build::Elf;
use sp1_core_executor::SP1ContextBuilder;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::SP1VerifyingKey;

#[derive(Clone)]
/// A proving key for the SP1 prover.
///
/// Contains only the minimal information required to implement the `ProvingKey` trait.
pub struct SP1ProvingKey {
    /// Verifying key for verifying a proof created with this proving key
    pub(crate) vk: SP1VerifyingKey,
    /// ELF of the program to be proven
    pub(crate) elf: Elf,
}

impl SP1ProvingKey {
    /// Creates a new `SP1ProvingKey` from a verifying key and ELF.
    #[must_use]
    pub fn new(vk: SP1VerifyingKey, elf: Elf) -> Self {
        Self { vk, elf }
    }
}

impl ProvingKey for SP1ProvingKey {
    fn verifying_key(&self) -> &SP1VerifyingKey {
        &self.vk
    }

    fn elf(&self) -> &Elf {
        &self.elf
    }
}

/// A unified collection of methods for all prover types.
pub trait ProveRequest<'a, P>
where
    Self: IntoSendFutureResult<SP1ProofWithPublicValues, P::Error> + Sized + Send,
    P: Prover + 'a,
{
    /// Get the base request for the prover.
    fn base(&mut self) -> &mut BaseProveRequest<'a, P>;

    /// Set the proof mode to the given [`SP1ProofKind`].
    ///
    /// # Details
    /// This method is useful for setting the proof mode to a custom mode.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{Elf, ProveRequest, Prover, ProverClient, SP1ProofMode, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().cpu().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let proof = client.prove(&pk, stdin).mode(SP1ProofMode::Groth16).await.unwrap();
    /// });
    /// ```
    #[must_use]
    fn mode(mut self, mode: SP1ProofMode) -> Self {
        self.base().mode(mode);
        self
    }

    /// Set the proof kind to [`SP1ProofKind::Compressed`] mode.
    ///
    /// # Details
    /// This mode produces a proof that is of constant size, regardless of the number of cycles. It
    /// takes longer to prove than [`SP1ProofKind::Core`] due to the need to recursively aggregate
    /// proofs into a single proof.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().cpu().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let proof = client.prove(&pk, stdin).compressed().await.unwrap();
    /// });
    /// ```
    #[must_use]
    fn compressed(mut self) -> Self {
        self.base().compressed();
        self
    }

    /// Set the proof mode to [`SP1ProofKind::Plonk`] mode.
    ///
    /// # Details
    /// This mode produces a const size PLONK proof that can be verified on chain for roughly ~300k
    /// gas. This mode is useful for producing a maximally small proof that can be verified on
    /// chain. For more efficient SNARK wrapping, you can use the [`SP1ProofKind::Groth16`] mode but
    /// this mode is more .
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().cpu().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let builder = client.prove(&pk, stdin).plonk().await;
    /// });
    /// ```
    #[must_use]
    fn plonk(mut self) -> Self {
        self.base().plonk();
        self
    }

    /// Set the proof mode to [`SP1ProofKind::Groth16`] mode.
    ///
    /// # Details
    /// This mode produces a Groth16 proof that can be verified on chain for roughly ~100k gas. This
    /// mode is useful for producing a proof that can be verified on chain with minimal gas.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().cpu().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let proof = client.prove(&pk, stdin).groth16().await.unwrap();
    /// });
    /// ```
    #[must_use]
    fn groth16(mut self) -> Self {
        self.base().groth16();
        self
    }

    /// Set the proof kind to [`SP1ProofKind::Core`] mode.
    ///
    /// # Details
    /// This is the default mode for the prover. The proofs grow linearly in size with the number
    /// of cycles.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().cpu().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let proof = client.prove(&pk, stdin).core().await.unwrap();
    /// });
    /// ```
    #[must_use]
    fn core(mut self) -> Self {
        self.base().core();
        self
    }

    /// Set the maximum number of cpu cycles to use for execution.
    ///
    /// # Details
    /// If the cycle limit is exceeded, execution will return
    /// [`sp1_core_executor::ExecutionError::ExceededCycleLimit`].
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().cpu().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let proof = client.prove(&pk, stdin).cycle_limit(1000000).await.unwrap();
    /// });
    /// ```
    #[must_use]
    fn cycle_limit(mut self, cycle_limit: u64) -> Self {
        self.base().cycle_limit(cycle_limit);
        self
    }

    /// Whether to enable deferred proof verification in the executor.
    ///
    /// # Arguments
    /// * `value` - Whether to enable deferred proof verification in the executor.
    ///
    /// # Details
    /// Default: `true`. If set to `false`, the executor will skip deferred proof verification.
    /// This is useful for reducing the execution time of the program and optimistically assuming
    /// that the deferred proofs are correct. Can also be used for mock proof setups that require
    /// verifying mock compressed proofs.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().cpu().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let proof = client.prove(&pk, stdin).deferred_proof_verification(false).await.unwrap();
    /// });
    /// ```
    #[must_use]
    fn deferred_proof_verification(mut self, value: bool) -> Self {
        self.base().deferred_proof_verification(value);
        self
    }

    /// Set the expected exit code of the program.
    ///
    /// # Arguments
    /// * `code` - The expected exit code of the program.
    #[must_use]
    fn expected_exit_code(mut self, code: StatusCode) -> Self {
        self.base().expected_exit_code(code);
        self
    }

    /// Set the proof nonce for this execution.
    ///
    /// The nonce ensures each proof is unique even for identical programs and inputs.
    /// If not provided, will default to 0.
    ///
    /// # Arguments
    /// * `nonce` - A 4-element array representing 128 bits of nonce data.
    #[must_use]
    fn with_proof_nonce(mut self, nonce: [u32; 4]) -> Self {
        self.base().context_builder.proof_nonce(nonce);
        self
    }
}

/// The base prove request for a prover.
///
/// This exposes all the options that are shared across different prover types.
pub struct BaseProveRequest<'a, P: Prover> {
    pub(crate) prover: &'a P,
    pub(crate) pk: &'a P::ProvingKey,
    pub(crate) stdin: SP1Stdin,
    pub(crate) mode: SP1ProofMode,
    pub(crate) context_builder: SP1ContextBuilder<'static>,
}

impl<'a, P: Prover> BaseProveRequest<'a, P> {
    /// Create a new [`BaseProveRequest`] with the given prover, proving key, and stdin.
    ///
    /// # Arguments
    /// * `prover` - The prover to use.
    /// * `pk` - The proving key to use.
    /// * `stdin` - The stdin to use.
    pub const fn new(prover: &'a P, pk: &'a P::ProvingKey, stdin: SP1Stdin) -> Self {
        Self {
            prover,
            pk,
            stdin,
            mode: SP1ProofMode::Core,
            context_builder: SP1ContextBuilder::new(),
        }
    }

    /// See [`ProveRequest::compressed`].
    pub fn compressed(&mut self) {
        self.mode = SP1ProofMode::Compressed;
    }

    /// See [`ProveRequest::plonk`].
    pub fn plonk(&mut self) {
        self.mode = SP1ProofMode::Plonk;
    }

    /// See [`ProveRequest::groth16`].
    pub fn groth16(&mut self) {
        self.mode = SP1ProofMode::Groth16;
    }

    /// See [`ProveRequest::core`].
    pub fn core(&mut self) {
        self.mode = SP1ProofMode::Core;
    }

    /// See [`ProveRequest::mode`].
    pub fn mode(&mut self, mode: SP1ProofMode) {
        self.mode = mode;
    }

    /// See [`ProveRequest::cycle_limit`].
    pub fn cycle_limit(&mut self, cycle_limit: u64) {
        self.context_builder.max_cycles(cycle_limit);
    }

    /// See [`ProveRequest::deferred_proof_verification`].
    pub fn deferred_proof_verification(&mut self, value: bool) {
        self.context_builder.set_deferred_proof_verification(value);
    }

    /// See [`ProveRequest::expected_exit_code`].
    pub fn expected_exit_code(&mut self, code: StatusCode) {
        self.context_builder.expected_exit_code(code);
    }

    pub fn with_nonce(&mut self, nonce: [u32; 4]) {
        self.context_builder.proof_nonce(nonce);
    }
}
