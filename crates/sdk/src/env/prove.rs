use anyhow::Result;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{components::CpuProverComponents, SP1ProvingKey};

use crate::{Prover, SP1ProofMode, SP1ProofWithPublicValues};

/// Builder to prepare and configure proving execution of a program on an input.
/// May be run with [`Self::run`].
pub struct EnvProveBuilder<'a> {
    pub(crate) prover: &'a dyn Prover<CpuProverComponents>,
    pub(crate) mode: SP1ProofMode,
    pub(crate) pk: &'a SP1ProvingKey,
    pub(crate) stdin: SP1Stdin,
}

impl<'a> EnvProveBuilder<'a> {
    /// Set the proof kind to [`SP1ProofMode::Core`] mode.
    ///
    /// # Details
    /// This is the default mode for the prover. The proofs grow linearly in size with the number
    /// of cycles.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin, Prover};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::from_env();
    /// let (pk, vk) = client.setup(elf);
    /// let builder = client.prove(&pk, &stdin)
    ///     .core()
    ///     .run();
    /// ```
    pub fn core(mut self) -> Self {
        self.mode = SP1ProofMode::Core;
        self
    }

    /// Set the proof kind to [`SP1ProofMode::Compressed`] mode.
    ///
    /// # Details
    /// This mode produces a proof that is of constant size, regardless of the number of cycles. It
    /// takes longer to prove than [`SP1ProofMode::Core`] due to the need to recursively aggregate
    /// proofs into a single proof.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin, Prover};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::from_env();
    /// let (pk, vk) = client.setup(elf);
    /// let builder = client.prove(&pk, &stdin)
    ///     .compressed()
    ///     .run();
    /// ```
    pub fn compressed(mut self) -> Self {
        self.mode = SP1ProofMode::Compressed;
        self
    }

    /// Set the proof mode to [`SP1ProofMode::Plonk`] mode.
    ///
    /// # Details
    /// This mode produces a const size PLONK proof that can be verified on chain for roughly ~300k
    /// gas. This mode is useful for producing a maximally small proof that can be verified on
    /// chain. For more efficient SNARK wrapping, you can use the [`SP1ProofMode::Groth16`] mode but
    /// this mode is more .
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin, Prover};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::from_env();
    /// let (pk, vk) = client.setup(elf);
    /// let builder = client.prove(&pk, &stdin)
    ///     .plonk()
    ///     .run();
    /// ```
    pub fn plonk(mut self) -> Self {
        self.mode = SP1ProofMode::Plonk;
        self
    }

    /// Set the proof mode to [`SP1ProofMode::Groth16`] mode.
    ///
    /// # Details
    /// This mode produces a Groth16 proof that can be verified on chain for roughly ~100k gas. This
    /// mode is useful for producing a proof that can be verified on chain with minimal gas.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin, Prover};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::from_env();
    /// let (pk, vk) = client.setup(elf);
    /// let builder = client.prove(&pk, &stdin)
    ///     .groth16()
    ///     .run();
    /// ```
    pub fn groth16(mut self) -> Self {
        self.mode = SP1ProofMode::Groth16;
        self
    }

    /// Set the proof mode to the given [`SP1ProofMode`].
    ///
    /// # Details
    /// This method is useful for setting the proof mode to a custom mode.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin, Prover, SP1ProofMode};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::from_env();
    /// let (pk, vk) = client.setup(elf);
    /// let builder = client.prove(&pk, &stdin)
    ///     .mode(SP1ProofMode::Groth16)
    ///     .run();
    /// ```
    pub fn mode(mut self, mode: SP1ProofMode) -> Self {
        self.mode = mode;
        self
    }

    /// Run the prover with the built arguments.
    ///
    /// # Details
    /// This method will run the prover with the built arguments. If the prover fails to run, the
    /// method will return an error.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin, Prover};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::from_env();
    /// let (pk, vk) = client.setup(elf);
    /// let proof = client.prove(&pk, &stdin)
    ///     .run()
    ///     .unwrap();
    /// ```
    pub fn run(self) -> Result<SP1ProofWithPublicValues> {
        let Self { prover, mode: kind, pk, stdin } = self;

        // Dump the program and stdin to files for debugging if `SP1_DUMP` is set.
        crate::utils::sp1_dump(&pk.elf, &stdin);

        prover.prove(pk, &stdin, kind)
    }
}
